"""
LANPool UDP Broadcast Discovery Service (core/peer_discovery.py)
Implements Rule A (Self-Echo Drop), Rule B (Physical LAN IP via net_utils),
and Rule C (SO_REUSEADDR + SO_REUSEPORT multi-node local testing & broadcast).
Enforces Findings 9 & 10: Beacon validation (±60s timestamp window, IP safety checks).
"""

import asyncio
import ipaddress
import json
import logging
import socket
import time
import math
import uuid
import hashlib
import httpx
from typing import Any, Optional
from core.peer_auth import beacon_signature, trusted_beacon, verify_content, send_bounded, peer_client, peer_url
from config import PEER_SECRET

from config import BEACON_INTERVAL_SECONDS, PEER_TTL_SECONDS, UDP_DISCOVERY_PORT
from core.peer_registry import PeerRegistry, NODE_ID_PATTERN

logger = logging.getLogger("lanpool.discovery")


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP datagram protocol forwarding incoming beacons to PeerDiscovery."""

    def __init__(self, discovery: "PeerDiscovery"):
        self.discovery = discovery

    def datagram_received(self, data: bytes, addr: tuple):
        self.discovery.handle_datagram(data, addr)

    def error_received(self, exc: Exception):
        logger.warning(f"UDP datagram listener error: {exc}")


class PeerDiscovery:
    def __init__(
        self,
        node_id: str,
        http_port: int,
        lan_ip: str,
        registry: PeerRegistry,
        udp_port: int = UDP_DISCOVERY_PORT,
        beacon_interval: float = BEACON_INTERVAL_SECONDS,
        peer_ttl: float = PEER_TTL_SECONDS,
        qos_manager: Optional[Any] = None,
        scheme: str = "http",
    ):
        self.node_id = node_id
        self.http_port = http_port
        self.lan_ip = lan_ip
        self.registry = registry
        self.udp_port = udp_port
        self.beacon_interval = beacon_interval
        self.peer_ttl = peer_ttl
        self.qos_manager = qos_manager
        self.scheme = scheme

        self.listener_running = False
        self.reuse_address = True
        self.reuse_port = False
        self.last_beacon_sent: Optional[float] = None
        self.last_beacon_received: Optional[float] = None
        self.last_error: Optional[str] = None

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[DiscoveryProtocol] = None

        self._broadcast_task: Optional[asyncio.Task] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def start(self):
        """Starts UDP listener, beacon broadcaster, and peer reaper loops."""
        self._stop_event.clear()
        loop = asyncio.get_running_loop()
        sock: Optional[socket.socket] = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Rule C: SO_REUSEPORT for local multi-instance discovery.
            # Do NOT set SO_REUSEADDR when SO_REUSEPORT is available, because on Linux
            # SO_REUSEADDR allows coexisting with foreign sockets that bound 0.0.0.0:9999
            # with SO_REUSEADDR, defeating bind conflict detection and degraded mode.
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    self.reuse_port = True
                    self.reuse_address = False
                except OSError as opt_err:
                    logger.warning(f"SO_REUSEPORT not supported on this platform: {opt_err}")
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.reuse_port = False
                    self.reuse_address = True
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.reuse_port = False
                self.reuse_address = True

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setblocking(False)
            sock.bind(("0.0.0.0", self.udp_port))

            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DiscoveryProtocol(self),
                sock=sock,
            )
            self.transport = transport
            self.protocol = protocol
            self.listener_running = True
            logger.info(f"UDP Discovery listener active on 0.0.0.0:{self.udp_port}")
        except Exception as e:
            self.last_error = str(e)
            self.listener_running = False
            # Cleanly close socket if bind or endpoint failed
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            logger.error(f"Failed to bind UDP discovery listener on port {self.udp_port}: {e}")

        # Start background tasks
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        self._reaper_task = asyncio.create_task(self._reaper_loop())

    async def stop(self):
        """Cleanly stops background loops and closes UDP transport without leaking tasks."""
        self._stop_event.set()

        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
            self._broadcast_task = None

        if self._reaper_task:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
            self._reaper_task = None

        if self.transport and not self.transport.is_closing():
            self.transport.close()
            self.transport = None

        self.listener_running = False

    def handle_datagram(self, data: bytes, addr: tuple):
        """Parses and validates incoming UDP beacon packets (Findings 9, 10)."""
        try:
            packet = json.loads(data.decode("utf-8"))
        except Exception:
            return

        if not isinstance(packet, dict):
            return

        peer_node_id = packet.get("node_id")
        peer_http_port = packet.get("http_port")
        peer_lan_ip = packet.get("lan_ip")
        ts = packet.get("timestamp")

        # Validate contract fields
        if not peer_node_id or not isinstance(peer_node_id, str):
            return
        if not isinstance(peer_http_port, int) or not (1 <= peer_http_port <= 65535):
            return
        if not peer_lan_ip or not isinstance(peer_lan_ip, str):
            return
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
            return

        # Finding 9: Timestamp window check (reject timestamps older or future by > 60s)
        now = time.time()
        if abs(now - ts) > 60.0:
            logger.debug(f"Rejected beacon with stale/future timestamp: {ts} (now: {now})")
            return

        # Finding 9: Validate peer_lan_ip as safe IPv4 address
        try:
            ip_obj = ipaddress.IPv4Address(peer_lan_ip.strip())
            if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local or str(ip_obj) == "255.255.255.255":
                return
            clean_lan_ip = str(ip_obj)
        except ValueError:
            return

        # Rule A: Self-echo prevention
        if peer_node_id == self.node_id:
            return

        share_pct = packet.get("share_pct", 30)
        game_mode = packet.get("game_mode", False)
        boosted = packet.get("boosted", False)
        if type(share_pct) is not int or not 0 <= share_pct <= 100 or type(game_mode) is not bool or type(boosted) is not bool:
            return
        if not NODE_ID_PATTERN.fullmatch(peer_node_id):
            return
        trusted = trusted_beacon(packet)
        scheme = packet.get("scheme", "http")
        if scheme not in ("http", "https"):
            return
        if PEER_SECRET and not trusted:
            return

        self.last_beacon_received = now
        self.registry.upsert_udp(
            node_id=peer_node_id,
            ip=addr[0],
            port=peer_http_port,
            lan_ip=clean_lan_ip,
            share_pct=share_pct,
            game_mode=game_mode,
            boosted=boosted,
            trusted=trusted,
            scheme=scheme,
        )

    def broadcast_beacon(self):
        """
        Broadcasts heartbeat beacon to 255.255.255.255 and 127.255.255.255 (Rule C),
        with fallback to 127.0.0.1. Includes QoS fields when QoS manager is configured.
        """
        beacon_data = {
            "node_id": self.node_id,
            "http_port": self.http_port,
            "lan_ip": self.lan_ip,
            "timestamp": time.time(),
            "scheme": self.scheme,
        }
        if self.qos_manager is not None:
            beacon_data["share_pct"] = getattr(self.qos_manager, "effective_share_pct", 30)
            beacon_data["game_mode"] = getattr(self.qos_manager, "effective_game_mode", False)
            beacon_data["boosted"] = getattr(self.qos_manager, "boosted", False)

        if PEER_SECRET:
            beacon_data["signature"] = beacon_signature(beacon_data)
        payload = json.dumps(beacon_data).encode("utf-8")

        sent_any = False
        targets = ("127.255.255.255",) if self.lan_ip.startswith("127.") else ("255.255.255.255", "127.255.255.255")
        for target in targets:
            try:
                if self.transport and not self.transport.is_closing():
                    self.transport.sendto(payload, (target, self.udp_port))
                    sent_any = True
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(payload, (target, self.udp_port))
                    s.close()
                    sent_any = True
            except Exception:
                pass

        if not sent_any:
            try:
                if self.transport and not self.transport.is_closing():
                    self.transport.sendto(payload, ("127.0.0.1", self.udp_port))
                    sent_any = True
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(payload, ("127.0.0.1", self.udp_port))
                    s.close()
                    sent_any = True
            except Exception:
                pass

        if sent_any:
            self.last_beacon_sent = time.time()

    async def _broadcast_loop(self):
        """Periodically broadcasts node identity beacons."""
        while not self._stop_event.is_set():
            try:
                self.broadcast_beacon()
            except Exception as e:
                logger.error(f"Error broadcasting beacon: {e}")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.beacon_interval)
            except asyncio.TimeoutError:
                pass

    async def _reaper_loop(self):
        """Periodically reaps expired UDP peer leases."""
        while not self._stop_event.is_set():
            try:
                async def refresh(peer):
                    if not peer.get("manual"):
                        return
                    nonce = uuid.uuid4().hex
                    try:
                        async with peer_client(2) as client:
                            response = await send_bounded(client, client.build_request("GET", peer_url(peer, "/api/health"), params={"nonce": nonce}))
                            response.raise_for_status()
                            data = response.json()
                            trusted = bool(data.get("nonce") == nonce and verify_content(hashlib.sha256(response.content).hexdigest(), response.headers.get("X-LANPool-Content-Signature", "")))
                            if not isinstance(data.get("node_id"), str) or not data["node_id"] or (PEER_SECRET and not trusted):
                                raise ValueError("Peer identity changed")
                            self.registry.refresh_health(peer["node_id"], data, trusted)
                    except (httpx.HTTPError, ValueError):
                        self.registry.refresh_health(peer["node_id"])
                await asyncio.gather(*(refresh(p) for p in self.registry.list_peers()))
                reaped = self.registry.reap_stale(self.peer_ttl)
                if reaped:
                    logger.info(f"Reaped stale UDP peers: {reaped}")
            except Exception as e:
                logger.error(f"Error in peer reaper loop: {e}")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.beacon_interval)
            except asyncio.TimeoutError:
                pass

    def get_diagnostics(self) -> dict:
        """Returns comprehensive network and UDP discovery diagnostics."""
        peer_counts = self.registry.counts()
        return {
            "node_id": self.node_id,
            "http_port": self.http_port,
            "lan_ip": self.lan_ip,
            "udp": {
                "listener_running": self.listener_running,
                "bind_host": "0.0.0.0",
                "port": self.udp_port,
                "reuse_address": self.reuse_address,
                "reuse_port": self.reuse_port if self.listener_running else False,
                "broadcast_targets": ["255.255.255.255", "127.255.255.255"],
                "beacon_interval_seconds": self.beacon_interval,
                "last_beacon_sent": self.last_beacon_sent,
                "last_beacon_received": self.last_beacon_received,
                "last_error": self.last_error,
            },
            "peers": {
                "total": peer_counts["total"],
                "udp": peer_counts["udp"],
                "manual": peer_counts["manual"],
                "stale_after_seconds": self.peer_ttl,
            },
            "firewall_hint": (
                f"If UDP discovery fails across LAN, ensure UDP port {self.udp_port} "
                "is allowed in firewall settings, or use POST /api/peers/add to connect directly."
            ),
        }
