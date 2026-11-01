#!/usr/bin/env python3
"""
LANPool Stage 6: One-Click 3-Node College Demo Cluster & Throttled Origin Server
File: demo_cluster.py

Architecture:
- Demo Origin Server (port 8090 by default): Range-capable HTTP/1.1 server serving
  deterministic virtual files with realistic per-stream bandwidth throttling:
    * /files/game-update-60mb.pak (60 MB — 6 micro-chunks of 10 MB)
    * /files/ubuntu-patch-35mb.iso (35 MB — 4 micro-chunks)
    * /files/driver-bundle-20mb.bin (20 MB — 2 micro-chunks)
- Node 1 (port 8001): Primary Requester PC (Default 30% share_pct)
- Node 2 (port 8002): Idle Helper PC (Boosted 80% share_pct)
- Node 3 (port 8003): Gaming Helper PC (15% cap, Fullscreen Game Mode simulation)

Usage:
  python3 demo_cluster.py                  # Interactive live presentation mode
  python3 demo_cluster.py --no-browser     # Headless interactive (no browser pop)
  python3 demo_cluster.py --headless-check # Automated CI/CD verification gate
"""

import argparse
import hashlib
import http.server
import json
import logging
import os
import re
import shutil
import signal
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

def demo_get(url, **kwargs):
    kwargs.setdefault("headers", {"X-LANPool-Token": os.environ.get("LANPOOL_API_TOKEN", "")})
    kwargs.setdefault("trust_env", False)
    return httpx.get(url, **kwargs)


def demo_post(url, **kwargs):
    kwargs.setdefault("headers", {"X-LANPool-Token": os.environ.get("LANPOOL_API_TOKEN", "")})
    kwargs.setdefault("trust_env", False)
    return httpx.post(url, **kwargs)


PROJECT_ROOT = Path(__file__).resolve().parent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("demo_cluster")


# ==============================================================================
# Deterministic Payload Generation
# ==============================================================================

DEMO_FILE_SPECS = {
    "game-update-60mb.pak": 60 * 1024 * 1024,
    "ubuntu-patch-35mb.iso": 35 * 1024 * 1024,
    "driver-bundle-20mb.bin": 20 * 1024 * 1024,
}


def generate_file_payload(filename: str, size: int) -> Tuple[bytes, str]:
    """Generates deterministic byte payload seeded by filename with minimal RAM churn."""
    data = hashlib.shake_256(("LANPool-demo-v2-" + filename).encode()).digest(size)
    sha = hashlib.sha256(data).hexdigest()
    return data, sha


# Pre-generate payloads for instant zero-lag serving
ORIGIN_PAYLOADS: Dict[str, bytes] = {}
ORIGIN_SHAS: Dict[str, str] = {}
ORIGIN_ETAGS: Dict[str, str] = {}

for fname, fsize in DEMO_FILE_SPECS.items():
    p_bytes, p_sha = generate_file_payload(fname, fsize)
    ORIGIN_PAYLOADS[fname] = p_bytes
    ORIGIN_SHAS[fname] = p_sha
    ORIGIN_ETAGS[fname] = f'"{p_sha[:16]}"'


# ==============================================================================
# Throttled Range-Capable Demo Origin Server
# ==============================================================================

class ThrottledOriginHandler(http.server.BaseHTTPRequestHandler):
    """
    Range-capable HTTP/1.1 Origin server supporting:
    - GET /files/<filename> with Range: bytes=start-end (206 Partial Content)
    - HEAD /files/<filename> (200 OK with Content-Length & Accept-Ranges)
    - GET /api/health (200 OK)
    - Bandwidth throttling (~4-8 MB/s in demo mode, fast in headless mode)
    """

    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.lstrip("/")

        if path.startswith("files/"):
            fname = path[len("files/") :]
            if fname in ORIGIN_PAYLOADS:
                size = len(ORIGIN_PAYLOADS[fname])
                etag = ORIGIN_ETAGS[fname]
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", etag)
                self.end_headers()
                return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.lstrip("/")

        if path in ("api/health", "health"):
            body = json.dumps({"status": "ok", "service": "demo_origin"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not path.startswith("files/"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        fname = path[len("files/") :]
        if fname not in ORIGIN_PAYLOADS:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        payload = ORIGIN_PAYLOADS[fname]
        total_len = len(payload)
        etag = ORIGIN_ETAGS[fname]

        rng_header = self.headers.get("Range", "").strip()
        delay_per_mb = getattr(self.server, "throttle_delay_per_mb", 0.08)

        if rng_header:
            m = re.match(r"bytes=(\d+)-(\d*)", rng_header)
            if not m:
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else total_len - 1
            end = min(end, total_len - 1)

            if start > end or start >= total_len:
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            chunk_len = end - start + 1
            chunk_data = payload[start : end + 1]

            # Simulate realistic WAN latency per 10 MB micro-chunk
            if delay_per_mb > 0:
                sleep_dur = (chunk_len / (1024 * 1024)) * delay_per_mb
                time.sleep(min(sleep_dur, 1.5))

            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Range", f"bytes {start}-{end}/{total_len}")
            self.send_header("Content-Length", str(chunk_len))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.end_headers()

            try:
                # Stream in 64KB blocks
                block_size = 65536
                for offset in range(0, chunk_len, block_size):
                    self.wfile.write(chunk_data[offset : offset + block_size])
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            # Full 200 GET
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total_len))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.end_headers()

            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, format, *args):
        # Suppress verbose origin request logging
        pass


class ThreadedOriginServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ==============================================================================
# Demo Cluster Manager
# ==============================================================================

class DemoClusterManager:
    """
    Manages the lifecycle of a 3-node LANPool cluster + origin server:
    - Node 1: Primary Requester (default 30% QoS)
    - Node 2: Idle Helper (80% Boosted)
    - Node 3: Gaming PC (15% Cap, Game Mode Simulation)
    """

    def __init__(
        self,
        base_port: int = 8001,
        origin_port: Optional[int] = None,
        headless: bool = False,
        runtime_dir: Optional[Path] = None,
    ):
        self.base_port = base_port
        self.node1_port = base_port
        if not 1 <= base_port <= 65535:
            raise ValueError("base-port must be 1..65535")
        used = {base_port}
        def free_port():
            while True:
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                if port not in used:
                    used.add(port)
                    return port
        self.node2_port = 8002 if base_port == 8001 else free_port()
        self.node3_port = 8003 if base_port == 8001 else free_port()
        self.origin_port = origin_port or (8090 if base_port == 8001 else free_port())
        self.peer_secret = os.environ.get("LANPOOL_PEER_SECRET") or secrets.token_hex(32)
        self.log_paths = {}
        self._port_holds = {}
        self.headless = headless

        self.runtime_dir = runtime_dir or (PROJECT_ROOT / "demo_runtime")
        self.origin_server: Optional[ThreadedOriginServer] = None
        self.origin_thread: Optional[threading.Thread] = None

        self.node_procs: Dict[int, subprocess.Popen] = {}
        self.node_dirs: Dict[int, Dict[str, Path]] = {}

    def start_origin_server(self, throttle_delay: float) -> None:
        """Starts the Range-capable throttled demo origin server."""
        self.origin_server = ThreadedOriginServer(("127.0.0.1", self.origin_port), ThrottledOriginHandler)
        self.origin_server.throttle_delay_per_mb = throttle_delay
        self.origin_thread = threading.Thread(target=self.origin_server.serve_forever, daemon=True)
        self.origin_thread.start()
        logger.info(f"Demo Origin Server online at http://127.0.0.1:{self.origin_port} (throttle={throttle_delay}s/MB)")

    def start_node(self, port: int) -> subprocess.Popen:
        """Spawns an isolated LANPool daemon on the designated port."""
        node_dir = self.runtime_dir / f"node_{port}"
        cache_dir = node_dir / "cache"
        download_dir = node_dir / "downloads"

        cache_dir.mkdir(parents=True, exist_ok=True)
        download_dir.mkdir(parents=True, exist_ok=True)
        self.node_dirs[port] = {"cache": cache_dir, "downloads": download_dir}

        cmd = [
            sys.executable,
            "main.py",
            "--port",
            str(port),
            "--cache-dir",
            str(cache_dir),
            "--download-dir",
            str(download_dir),
        ]

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["LANPOOL_ALLOW_LOOPBACK"] = "1"
        env["LANPOOL_PEER_SECRET"] = self.peer_secret

        self.log_paths[port] = node_dir / "node.log"
        hold = self._port_holds.pop(port, None)
        if hold:
            hold.close()
        with self.log_paths[port].open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
        self.node_procs[port] = proc
        return proc

    def wait_for_node_health(self, port: int, timeout: float = 12.0) -> dict:
        """Polls /api/health until responsive."""
        url = f"http://127.0.0.1:{port}/api/health"
        start = time.time()
        last_err = None
        while time.time() - start < timeout:
            if self.node_procs[port].poll() is not None:
                log = self.log_paths[port].read_text(encoding="utf-8", errors="replace")[-4000:]
                raise RuntimeError(f"Node {port} exited early: {log}")
            try:
                resp = demo_get(url, timeout=1.0)
                if resp.status_code == 200:
                    return resp.json()
            except Exception as e:
                last_err = e
            time.sleep(0.1)
        raise TimeoutError(f"Node on port {port} failed to respond at {url}: {last_err}")

    def boot_cluster(self, fast_mode: bool = False) -> None:
        """Boots origin server, spawns 3 nodes, cross-registers peers, and configures QoS roles."""
        throttle_delay = 0.015 if fast_mode else 0.12
        ports = (self.node1_port, self.node2_port, self.node3_port, self.origin_port)
        if len(set(ports)) != 4 or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("Cluster requires four distinct valid ports")
        try:
            for port in ports:
                hold = socket.socket()
                try:
                    hold.bind(("127.0.0.1", port))
                except BaseException:
                    hold.close()
                    raise
                self._port_holds[port] = hold
            self._port_holds.pop(self.origin_port).close()
            self.start_origin_server(throttle_delay)
        except BaseException:
            self.stop_cluster(cleanup_runtime=False)
            raise

        # Spawn all 3 nodes
        for port in (self.node1_port, self.node2_port, self.node3_port):
            self.start_node(port)

        # Wait for all nodes to become healthy
        for port in (self.node1_port, self.node2_port, self.node3_port):
            self.wait_for_node_health(port)
            logger.info(f"Node on port {port} confirmed healthy.")

        # Cross-register all 3 nodes for deterministic peer discovery
        ports = [self.node1_port, self.node2_port, self.node3_port]
        for src_port in ports:
            for dst_port in ports:
                if src_port != dst_port:
                    try:
                        demo_post(
                            f"http://127.0.0.1:{src_port}/api/peers/add",
                            json={"ip": "127.0.0.1", "port": dst_port},
                            timeout=3.0,
                        )
                    except Exception as e:
                        logger.warning(f"Error registering peer {dst_port} with {src_port}: {e}")

        # Configure Node Roles (QoS Settings)
        # Node 1: Primary Requester (Default 30%)
        demo_post(
            f"http://127.0.0.1:{self.node1_port}/api/qos/update",
            json={"share_pct": 30},
            timeout=3.0,
        )

        # Node 2: Idle Helper (Boosted 80%)
        demo_post(
            f"http://127.0.0.1:{self.node2_port}/api/qos/update",
            json={"share_pct": 80, "boosted": True},
            timeout=3.0,
        )

        # Node 3: Gaming PC (Fullscreen Game Mode simulated -> 15% cap)
        demo_post(
            f"http://127.0.0.1:{self.node3_port}/api/qos/update",
            json={"simulate_game_mode": True},
            timeout=3.0,
        )

        logger.info("3-Node Cluster initialization complete and roles assigned.")

    def run_headless_check(self) -> None:
        """
        Executes complete automated validation of the cluster:
        - Verifies 3-node cross-registration and role parameters
        - Executes cooperative 60 MB pooled download from Demo Origin
        - Verifies dual-source WAN + LAN telemetry and SHA-256 integrity
        - Verifies Broadcast Boost and Game Mode suppression
        """
        logger.info("Starting Stage 6 Headless Verification...")

        # 1. Verify Node 2 QoS
        q2 = demo_get(f"http://127.0.0.1:{self.node2_port}/api/qos/status", timeout=3.0).json()
        assert q2.get("boosted") is True, f"Node 2 should be boosted: {q2}"
        assert q2.get("effective_share_pct") == 80, f"Node 2 share should be 80: {q2}"

        # 2. Verify Node 3 QoS
        q3 = demo_get(f"http://127.0.0.1:{self.node3_port}/api/qos/status", timeout=3.0).json()
        assert q3.get("effective_game_mode") is True, f"Node 3 should have effective_game_mode=True: {q3}"
        assert q3.get("effective_share_pct") <= 15, f"Node 3 share should be <= 15: {q3}"

        # 3. Verify Peer Count on Node 1
        p1 = demo_get(f"http://127.0.0.1:{self.node1_port}/api/peers/list", timeout=3.0).json()
        peers = p1 if isinstance(p1, list) else p1.get("peers", [])
        assert len(peers) >= 2, f"Node 1 should discover at least 2 peers, got: {len(peers)}"

        # 4. Trigger 60 MB Pooled Download on Node 1 from Origin
        demo_url = f"http://127.0.0.1:{self.origin_port}/files/game-update-60mb.pak"
        dest_filename = "verified_game_update.pak"
        expected_sha = ORIGIN_SHAS["game-update-60mb.pak"]

        start_resp = demo_post(
            f"http://127.0.0.1:{self.node1_port}/api/download/start",
            json={"url": demo_url, "filename": dest_filename},
            timeout=5.0,
        )
        assert start_resp.status_code == 200, f"Download start failed: {start_resp.text}"
        job_id = start_resp.json()["job_id"]

        # Poll status until complete
        deadline = time.time() + 45.0
        final_status = None
        seen_workers = set()

        while time.time() < deadline:
            st = demo_get(
                f"http://127.0.0.1:{self.node1_port}/api/download/status",
                params={"job_id": job_id},
                timeout=3.0,
            ).json()

            for ch in st.get("chunks", []):
                w = ch.get("worker_id")
                if w:
                    seen_workers.add(w)

            if st.get("status") in ("completed", "failed"):
                final_status = st
                break
            time.sleep(0.05)

        assert final_status is not None, "Timed out waiting for 60MB pooled download to complete"
        assert final_status.get("status") == "completed", f"Download failed: {final_status}"
        assert final_status.get("sha256") == expected_sha, f"SHA mismatch: {final_status.get('sha256')}"

        # Assert Dual-Source Telemetry: both WAN and LAN bytes contributed
        assert final_status.get("lan_bytes", 0) > 0 or any(w.startswith("helper-") for w in seen_workers), (
            f"Cooperative pooling failed! lan_bytes={final_status.get('lan_bytes')}, seen_workers={seen_workers}"
        )
        assert final_status.get("wan_bytes", 0) > 0 or any(w.startswith("self-") for w in seen_workers), (
            f"Self WAN worker failed! wan_bytes={final_status.get('wan_bytes')}"
        )

        # Verify on-disk file integrity in Node 1 cache directory
        cached_matches = list(self.node_dirs[self.node1_port]["cache"].glob(f"{expected_sha}_*"))
        assert len(cached_matches) == 1, f"Expected 1 cached file in node cache, got: {cached_matches}"
        assert hashlib.sha256(cached_matches[0].read_bytes()).hexdigest() == expected_sha

        # 5. Verify Broadcast Boost Request & Suppression
        boost_resp = demo_post(
            f"http://127.0.0.1:{self.node1_port}/api/qos/boost-request",
            json={"filename": dest_filename, "total_size": DEMO_FILE_SPECS["game-update-60mb.pak"]},
            timeout=5.0,
        )
        assert boost_resp.status_code == 200, f"Boost broadcast failed: {boost_resp.text}"
        boost_data = boost_resp.json()
        assert boost_data.get("status") == "broadcast_complete"

        # Check Node 3 (Gaming PC) suppressed the notification
        q3_after = demo_get(f"http://127.0.0.1:{self.node3_port}/api/qos/status", timeout=3.0).json()
        assert q3_after.get("active_boost_request") is None, "Node 3 should suppress boost request popup in Game Mode"

        # Check Node 2 received the boost request
        q2_after = demo_get(f"http://127.0.0.1:{self.node2_port}/api/qos/status", timeout=3.0).json()
        assert q2_after.get("active_boost_request") is not None, "Node 2 should have received active boost request"

        print("\n" + "=" * 60)
        print("DEMO_CLUSTER_VERIFIED_OK")
        print("=" * 60 + "\n")
        logger.info("All Stage 6 headless assertions successfully passed.")

    def stop_cluster(self, cleanup_runtime: bool = True) -> None:
        """Terminates all nodes and shuts down origin server cleanly."""
        logger.info("Stopping demo cluster...")
        for hold in self._port_holds.values():
            hold.close()
        self._port_holds.clear()
        for port, proc in list(self.node_procs.items()):
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass

        self.node_procs.clear()

        if self.origin_server:
            try:
                self.origin_server.shutdown()
                self.origin_server.server_close()
            except Exception:
                pass
            self.origin_server = None

        if cleanup_runtime and self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir, ignore_errors=True)

        logger.info("Cluster stopped cleanly. Zero process leaks.")


# ==============================================================================
# Interactive ASCII Banner & CLI Entrypoint
# ==============================================================================

BANNER = r"""
================================================================================
  ██╗      █████╗ ███╗   ██╗██████╗  ██████╗  ██████╗ ██╗     
  ██║     ██╔══██╗████╗  ██║██╔══██╗██╔═══██╗██╔═══██╗██║     
  ██║     ███████║██╔██╗ ██║██████╔╝██║   ██║██║   ██║██║     
  ██║     ██╔══██║██║╚██╗██║██╔═══╝ ██║   ██║██║   ██║██║     
  ███████╗██║  ██║██║ ╚████║██║     ╚██████╔╝╚██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝  ╚═════╝ ╚══════╝
  Cooperative LAN Bandwidth-Aggregation & Cache Daemon (Stage 6)
================================================================================
"""


def main():
    parser = argparse.ArgumentParser(description="LANPool 3-Node Live Demo Cluster")
    parser.add_argument("--base-port", type=int, default=8001, help="Starting port for node cluster (default: 8001)")
    parser.add_argument("--origin-port", type=int, default=None, help="Port for Throttled Demo Origin CDN (default: 8090)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    parser.add_argument("--headless-check", action="store_true", help="Run automated verification gate and exit")
    parser.add_argument("--cleanup", action="store_true", help="Remove demo_runtime folder on exit")
    args = parser.parse_args()

    cluster = DemoClusterManager(
        base_port=args.base_port,
        origin_port=args.origin_port,
        headless=args.headless_check,
        runtime_dir=Path(tempfile.mkdtemp(prefix="lanpool_headless_")) if args.headless_check else None,
    )

    def handle_sigint(sig, frame):
        print("\n[Shutdown] Caught interrupt signal. Terminating cluster...")
        cluster.stop_cluster(cleanup_runtime=args.cleanup)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    if args.headless_check:
        try:
            cluster.boot_cluster(fast_mode=True)
            cluster.run_headless_check()
        finally:
            cluster.stop_cluster(cleanup_runtime=True)
        sys.exit(0)

    # Interactive Presentation Mode
    print(BANNER)
    print("🚀 Initializing 3-Node LANPool Live Demonstration Cluster...")
    try:
        cluster.boot_cluster(fast_mode=False)
    except BaseException:
        cluster.stop_cluster(cleanup_runtime=args.cleanup)
        raise

    origin_p = cluster.origin_port
    n1_p = cluster.node1_port
    n2_p = cluster.node2_port
    n3_p = cluster.node3_port

    print("-" * 80)
    print("📍 CLUSTER TOPOLOGY ONLINE & READY FOR EVALUATION:")
    print(f"  • Node 1 (Requester PC):  http://127.0.0.1:{n1_p}  [30% Default Share]")
    print(f"  • Node 2 (Idle Helper):   http://127.0.0.1:{n2_p}  [80% Boosted Share]")
    print(f"  • Node 3 (Gaming PC):     http://127.0.0.1:{n3_p}  [15% Game Mode Suppressed]")
    print(f"  • Throttled Origin CDN:   http://127.0.0.1:{origin_p}  [Range-Capable Origin]")
    print("-" * 80)
    print("⚡ DEMO PRESETS READY IN WEB UI:")
    print(f"  1. Click '[60 MB Pooled Demo]' on Node 1 dashboard (http://127.0.0.1:{n1_p})")
    print("  2. Watch the 10 MB chunk grid animate as Nodes 1, 2, and 3 pool bandwidth together!")
    print("  3. Switch to Node 2 dashboard to view outbound helper telemetry.")
    print("  4. Switch to Node 3 dashboard to verify Game Mode popup suppression.")
    print("-" * 80)
    print("Press Ctrl+C to stop all cluster nodes and origin server cleanly.")
    print("-" * 80 + "\n")

    if not args.no_browser:
        try:
            webbrowser.open(f"http://127.0.0.1:{n1_p}?origin_port={origin_p}")
        except Exception:
            pass

    # Keep cluster alive until interrupted
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        cluster.stop_cluster(cleanup_runtime=args.cleanup)
        print("Demo cluster stopped cleanly.")


if __name__ == "__main__":
    main()
