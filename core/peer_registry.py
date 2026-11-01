"""
LANPool Peer Registry (core/peer_registry.py)
Thread-safe in-memory peer table managing active LANPool nodes.
Maintains discovery provenance (UDP vs manual fallback), enforces self-echo rejection,
and provides TTL-based eviction for UDP peers while persisting manual overrides.
Enforces Finding 9 (MAX_UDP_PEERS = 256 capacity limit) and Finding 10 (IP safety validation).
"""

import ipaddress
import threading
import time
from typing import Dict, List, Optional

MAX_UDP_PEERS = 256


class PeerRegistry:
    def __init__(self, own_node_id: str, own_http_port: int, own_lan_ip: str):
        self.own_node_id = own_node_id
        self.own_http_port = own_http_port
        self.own_lan_ip = own_lan_ip
        self._lock = threading.RLock()
        self._peers: Dict[str, dict] = {}

    def is_self(self, ip: str, port: int, node_id: Optional[str] = None) -> bool:
        """Determines if a candidate peer matches this host instance."""
        if node_id and self.own_node_id and node_id == self.own_node_id:
            return True
        if port == self.own_http_port:
            if ip in ("127.0.0.1", "localhost", "0.0.0.0", self.own_lan_ip):
                return True
        return False

    def upsert_udp(
        self,
        node_id: str,
        ip: str,
        port: int,
        lan_ip: str,
        share_pct: int = 30,
        game_mode: bool = False,
        boosted: bool = False,
        trusted: bool = False,
        scheme: str = "http",
    ) -> Optional[dict]:
        """
        Inserts or updates a peer discovered via UDP broadcast beacon.
        Drops self-echo, removes stale records for restarted nodes on same (ip, port),
        and enforces MAX_UDP_PEERS capacity cap by evicting oldest UDP peer.
        Includes QoS fields: share_pct, game_mode, boosted (Safeguard #11).
        """
        if self.is_self(ip=ip, port=port, node_id=node_id):
            return None

        with self._lock:
            now = time.time()

            # Finding 9: Clean up any old entry with identical (ip, port) but different node_id
            was_manual = False
            colliding_keys = [
                k for k, p in self._peers.items()
                if k != node_id and p.get("ip") == ip and p.get("port") == port
            ]
            for col_k in colliding_keys:
                if self._peers[col_k].get("manual", False):
                    was_manual = True
                del self._peers[col_k]

            existing: Optional[dict] = self._peers.get(node_id)

            if existing is not None:
                existing["last_seen"] = now
                if lan_ip:
                    existing["lan_ip"] = lan_ip
                if not existing.get("manual") and (ip != "127.0.0.1" or existing.get("ip") in (None, "", "127.0.0.1")):
                    existing["ip"] = ip
                if not existing.get("manual"):
                    existing["port"] = port
                existing["node_id"] = node_id
                existing["share_pct"] = share_pct
                existing["game_mode"] = game_mode
                existing["boosted"] = boosted
                existing["trusted"] = trusted
                if not existing.get("manual"):
                    existing["scheme"] = scheme
                if was_manual:
                    existing["manual"] = True
                    existing["source"] = "manual"
                return dict(existing)

            # Finding 9: Enforce MAX_UDP_PEERS cap
            udp_peer_keys = [k for k, p in self._peers.items() if not p.get("manual", False)]
            if len(udp_peer_keys) >= MAX_UDP_PEERS:
                oldest_k = min(udp_peer_keys, key=lambda k: self._peers[k].get("last_seen", 0))
                del self._peers[oldest_k]

            peer = {
                "node_id": node_id,
                "ip": ip,
                "port": port,
                "lan_ip": lan_ip or ip,
                "source": "manual" if was_manual else "udp",
                "manual": was_manual,
                "share_pct": share_pct,
                "game_mode": game_mode,
                "boosted": boosted,
                "trusted": trusted,
                "scheme": scheme,
                "first_seen": now,
                "last_seen": now,
            }
            self._peers[node_id] = peer
            return dict(peer)

    def add_manual(
        self,
        ip: str,
        port: int,
        node_id: Optional[str] = None,
        lan_ip: Optional[str] = None,
        trusted: bool = False,
        scheme: str = "http",
    ) -> dict:
        """
        Manually adds a peer (typically via POST /api/peers/add fallback).
        Enforces self-rejection and IP safety validation (Finding 10).
        Updates existing UDP peer in place and sets manual=True.
        """
        raw_ip = (ip or "").strip()
        try:
            ip_obj = ipaddress.IPv4Address(raw_ip)
            if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local or str(ip_obj) == "255.255.255.255":
                raise ValueError(f"Prohibited peer IP: '{raw_ip}'. Cannot add unspecified, multicast, or broadcast address.")
            clean_ip = str(ip_obj)
        except ValueError as val_err:
            raise ValueError(f"Invalid peer IPv4 address: {val_err}")

        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}. Port must be between 1 and 65535.")

        if self.is_self(ip=clean_ip, port=port, node_id=node_id):
            raise ValueError("Cannot add self as a peer.")

        with self._lock:
            now = time.time()
            existing: Optional[dict] = None
            existing_key: Optional[str] = None

            if node_id and node_id in self._peers:
                existing_key = node_id
                existing = self._peers[node_id]
            else:
                for k, p in self._peers.items():
                    if p["ip"] == clean_ip and p["port"] == port:
                        existing_key = k
                        existing = p
                        break

            if existing is not None:
                existing["manual"] = True
                existing["source"] = "manual"
                existing["last_seen"] = now
                existing["trusted"] = trusted
                existing["scheme"] = scheme
                if node_id:
                    existing["node_id"] = node_id
                if lan_ip:
                    existing["lan_ip"] = lan_ip
                existing["ip"] = clean_ip
                existing["port"] = port

                target_key = node_id or existing_key
                if existing_key is not None and target_key is not None and existing_key != target_key:
                    del self._peers[existing_key]
                    self._peers[target_key] = existing

                return dict(existing)

            key = node_id or f"{clean_ip}:{port}"
            peer = {
                "node_id": node_id or "",
                "ip": clean_ip,
                "port": port,
                "lan_ip": lan_ip or clean_ip,
                "source": "manual",
                "manual": True,
                "share_pct": 30,
                "game_mode": False,
                "boosted": False,
                "trusted": trusted,
                "scheme": scheme,
                "first_seen": now,
                "last_seen": now,
            }
            self._peers[key] = peer
            return dict(peer)

    def get(self, key: str) -> Optional[dict]:
        """Looks up a peer by node_id or 'ip:port' key."""
        with self._lock:
            if key in self._peers:
                return dict(self._peers[key])
            for p in self._peers.values():
                if p.get("node_id") == key or f"{p.get('ip')}:{p.get('port')}" == key:
                    return dict(p)
            return None

    def list_peers(self) -> List[dict]:
        """Returns JSON-ready list of active peer dicts with live age_seconds and QoS fields."""
        with self._lock:
            now = time.time()
            result = []
            for p in self._peers.values():
                d = dict(p)
                d.setdefault("share_pct", 30)
                d.setdefault("game_mode", False)
                d.setdefault("boosted", False)
                d["age_seconds"] = max(0.0, round(now - p.get("last_seen", now), 2))
                d["available"] = now - p.get("last_seen", 0) <= 15
                result.append(d)
            return sorted(result, key=lambda x: x["last_seen"], reverse=True)

    def counts(self) -> dict:
        """Returns total, UDP, and manual peer counts."""
        with self._lock:
            total = len(self._peers)
            manual = sum(1 for p in self._peers.values() if p.get("manual", False))
            udp = total - manual
            return {"total": total, "udp": udp, "manual": manual}

    def refresh_health(self, node_id, health=None, trusted=False):
        """Manual peers remain configured, but availability/QoS use a live lease."""
        with self._lock:
            peer = self._peers.get(node_id)
            if not peer:
                return
            if health is None:
                peer["last_seen"] = 0
                return
            qos = health.get("qos", {})
            share = qos.get("effective_share_pct", 30)
            if type(share) is not int or not 0 <= share <= 100:
                return
            new_id = health.get("node_id", node_id)
            if trusted and isinstance(new_id, str) and new_id and len(new_id) <= 64 and new_id != node_id:
                if self.is_self(peer["ip"], peer["port"], new_id):
                    return
                self._peers.pop(node_id)
                peer["node_id"] = new_id
                self._peers[new_id] = peer
            peer.update(last_seen=time.time(), trusted=trusted, share_pct=share, game_mode=bool(qos.get("effective_game_mode")), boosted=bool(qos.get("boosted")))

    def reap_stale(self, ttl_seconds: float) -> List[str]:
        """
        Reaps stale UDP peers where (now - last_seen > ttl_seconds).
        Manually added peers (manual=True) persist and are never reaped.
        Returns the list of reaped node_ids / keys.
        """
        with self._lock:
            now = time.time()
            reaped: List[str] = []
            for key, peer in list(self._peers.items()):
                if not peer.get("manual", False):
                    if now - peer.get("last_seen", 0) > ttl_seconds:
                        reaped.append(key)
                        del self._peers[key]
            return reaped
