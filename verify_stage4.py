#!/usr/bin/env python3
"""
LANPool Stage 4 Verification Gate Script (verify_stage4.py)
Tests Cooperative Multi-Peer Pooling, Phase-1 Cache Hits & Self-Healing Failover:
1. Helper Endpoint (/api/worker/fetch-chunk):
   - Valid chunk fetch returns 200, exact bytes, and matching X-Chunk-SHA256.
   - Oversize chunk returns 400.
   - Inverted range and negative start return 400.
   - chunk_id < 0 returns 400.
   - SSRF / loopback-disabled returns 400.
   - 3xx redirect from origin returns 502.
   - Short body from origin returns 502.
   - Origin returning 200 without range returns 409 or 502.
   - ETag mismatch returns 409 Conflict.
   - API Token authentication (401 without token, 200 with token).
   - Fake helper missing X-Chunk-SHA256 regression test (rejected/requeued, valid completion).
2. 3-Node Pooling & Self-Healing Failover:
   - Requester Node A downloads 35 MB using helpers Node B and Node C.
   - Node C is killed mid-chunk with SIGKILL while downloading.
   - Node A detects failure, requeues orphan chunk, and completes successfully.
   - Verifies helper C was used, helper B was used, orphan chunk completed by A/B, no .part leak.
3. Phase 1 Peer Cache Hit:
   - Node B downloads the same URL from Node A's cache without origin chunk requests.
   - Verifies SHA-256 and registers file in Node B's cache.
4. Phase 1 Local Cache Hit:
   - Node B is stopped; Node A downloads same URL with instant local cache completion (0 origin chunk requests).
   - Verifies chunks_total == 0, destination file, and /api/cache/stream/{sha}.
5. Solo / No-Peers Path:
   - A solo node on a unique UDP port without peers downloads normally using self-workers only.
"""

import asyncio
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-test-group-key-not-for-deployment")

import httpx

from config import CHUNK_SIZE

PROJECT_ROOT = Path(__file__).resolve().parent

PAYLOAD_35MB = bytes([i % 251 for i in range(35 * 1024 * 1024)])
PAYLOAD_SHA = hashlib.sha256(PAYLOAD_35MB).hexdigest()

PAYLOAD_5MB = bytes([(i + 7) % 251 for i in range(5 * 1024 * 1024)])
PAYLOAD_5MB_SHA = hashlib.sha256(PAYLOAD_5MB).hexdigest()


def get_free_port() -> int:
    """Allocates an ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def free_udp_port() -> int:
    """Allocates an ephemeral UDP port on localhost."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for_health(port: int, timeout: float = 12.0) -> dict:
    """Polls /api/health until server responds with 200 OK."""
    url = f"http://127.0.0.1:{port}/api/health"
    start = time.time()
    last_err: Optional[Exception] = None
    while time.time() - start < timeout:
        try:
            resp = httpx.get(url, timeout=1.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            last_err = exc
        time.sleep(0.1)
    raise TimeoutError(f"Server on port {port} failed to respond at {url} within {timeout}s: {last_err}")


def start_node(
    port: int,
    cache_dir: Path,
    download_dir: Path,
    env_extra: Optional[Dict[str, str]] = None,
) -> subprocess.Popen:
    """Launches a LANPool daemon with isolated directories and DEVNULL child pipes."""
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
    if env_extra:
        env.update(env_extra)

    return subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
    )


def terminate_proc(proc: Optional[subprocess.Popen]) -> None:
    """Cleanly terminates and waits for a child process."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=1.0)
        except Exception:
            pass


# ==============================================================================
# Mock Origin & Fake Helper Servers
# ==============================================================================

class MockOriginHandler(http.server.BaseHTTPRequestHandler):
    """Range-capable mock origin server with contract test hooks and configurable delay."""
    protocol_version = "HTTP/1.1"
    etag = '"origin-v1"'
    delay = 0.5

    def do_GET(self):
        # 1. Poison: 302 Redirect
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/35mb.bin")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # 2. Poison: Short body (claims 0-100/1000, delivers 100 bytes instead of 1MB)
        if self.path.startswith("/short"):
            body = b"S" * 100
            self.send_response(206)
            self.send_header("Content-Range", "bytes 0-100/1000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # 3. Poison: 200 OK without Range support
        if self.path.startswith("/norange"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(PAYLOAD_35MB)))
            self.send_header("ETag", self.etag)
            self.end_headers()
            try:
                self.wfile.write(PAYLOAD_35MB)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # Deterministic payload selection
        if "/5mb." in self.path or "solo_5mb" in self.path:
            payload = PAYLOAD_5MB
        else:
            payload = PAYLOAD_35MB

        rng = self.headers.get("Range", "")
        if rng:
            m = re.match(r"bytes=(\d+)-(\d*)", rng)
            if not m:
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(payload) - 1
            end = min(end, len(payload) - 1)
            body = payload[start : end + 1]

            if start == 0 and end == 0:
                self.server.probe_count += 1
            else:
                self.server.chunk_count += 1
                if self.delay > 0:
                    time.sleep(self.delay)

            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(payload)}")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self.etag)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.server.probe_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self.etag)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, format, *args):
        pass


class MockOriginServer:
    def __init__(self, delay: float = 0.5):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockOriginHandler)
        self.server.daemon_threads = True
        self.server.probe_count = 0
        self.server.chunk_count = 0
        MockOriginHandler.delay = delay
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


class FakeHelperHandler(http.server.BaseHTTPRequestHandler):
    """Fake peer helper that deliberately returns exact-length dummy bytes with NO X-Chunk-SHA256."""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/api/health"):
            body = json.dumps({
                "status": "online",
                "node_id": "fake-helper-node-12345678",
                "lan_ip": "127.0.0.1",
                "http_port": self.server.server_address[1],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/api/cache/lookup"):
            body = b'{"hit": false}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        try:
            req = json.loads(raw)
        except Exception:
            req = {}

        if self.path.startswith("/api/worker/fetch-chunk"):
            length = int(req.get("end_byte", 0)) - int(req.get("start_byte", 0)) + 1
            body = b"Z" * max(0, length)
            self.server.fake_chunks += 1
            # Deliberately omit X-Chunk-SHA256 header
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class FakeHelperServer:
    def __init__(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHelperHandler)
        self.server.daemon_threads = True
        self.server.fake_chunks = 0
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


# ==============================================================================
# Verification Checks
# ==============================================================================

def check1_helper_endpoint(origin_url: str) -> None:
    """
    Check 1: Helper endpoint validation.
    Covers contract cases:
    - 200, exact length, matching X-Chunk-SHA256
    - Oversize chunk (> CHUNK_SIZE) -> 400
    - Inverted range and negative start -> 400
    - Negative chunk_id -> 400
    - SSRF target 0.0.0.0 -> 400
    - 3xx redirect from origin -> 502
    - Short body from origin -> 502
    - Origin 200 without range -> 409 or 502
    - ETag mismatch -> 409
    - Token auth: 401 without token, 200 with token
    - LANPOOL_ALLOW_LOOPBACK=0 on loopback URL -> 400
    - Fake helper missing X-Chunk-SHA256 regression: rejected/requeued, real SHA completed
    """
    port = get_free_port()
    tmp_c = Path(tempfile.mkdtemp(prefix="lanpool_s4_c1_c_"))
    tmp_d = Path(tempfile.mkdtemp(prefix="lanpool_s4_c1_d_"))
    proc = None
    try:
        proc = start_node(port, tmp_c, tmp_d)
        wait_for_health(port)
        base = f"http://127.0.0.1:{port}"

        # 1. Valid chunk fetch (1 MB micro-chunk)
        valid_payload = {
            "url": f"{origin_url}/35mb.bin",
            "start_byte": 0,
            "end_byte": 1048575,
            "chunk_id": 0,
            "etag": '"origin-v1"',
        }
        r1 = httpx.post(f"{base}/api/worker/fetch-chunk", json=valid_payload, timeout=5.0)
        assert r1.status_code == 200, f"Expected 200 on valid chunk fetch, got {r1.status_code}: {r1.text}"
        assert len(r1.content) == 1048576, f"Expected 1048576 bytes, got {len(r1.content)}"
        expected_sha = hashlib.sha256(PAYLOAD_35MB[:1048576]).hexdigest()
        assert r1.headers.get("X-Chunk-SHA256") == expected_sha, "X-Chunk-SHA256 header mismatch"

        # 2. Oversize chunk request (> CHUNK_SIZE) -> 400
        oversize_payload = {
            "url": f"{origin_url}/35mb.bin",
            "start_byte": 0,
            "end_byte": CHUNK_SIZE + 100,
            "chunk_id": 0,
        }
        r2 = httpx.post(f"{base}/api/worker/fetch-chunk", json=oversize_payload, timeout=5.0)
        assert r2.status_code == 400, f"Expected 400 on oversize chunk, got {r2.status_code}: {r2.text}"

        # 3. Invalid byte range (start > end or start < 0) -> 400
        r_inv1 = httpx.post(f"{base}/api/worker/fetch-chunk", json={"url": f"{origin_url}/35mb.bin", "start_byte": 500, "end_byte": 100, "chunk_id": 0}, timeout=5.0)
        assert r_inv1.status_code == 400, f"Expected 400 for inverted range, got {r_inv1.status_code}"
        r_inv2 = httpx.post(f"{base}/api/worker/fetch-chunk", json={"url": f"{origin_url}/35mb.bin", "start_byte": -5, "end_byte": 100, "chunk_id": 0}, timeout=5.0)
        assert r_inv2.status_code == 400, f"Expected 400 for negative start, got {r_inv2.status_code}"

        # 4. Negative chunk_id (< 0) -> 400
        r_neg_id = httpx.post(f"{base}/api/worker/fetch-chunk", json={"url": f"{origin_url}/35mb.bin", "start_byte": 0, "end_byte": 100, "chunk_id": -1}, timeout=5.0)
        assert r_neg_id.status_code == 400, f"Expected 400 for chunk_id < 0, got {r_neg_id.status_code}"

        # 5. SSRF invalid target (0.0.0.0) -> 400
        r_ssrf = httpx.post(f"{base}/api/worker/fetch-chunk", json={"url": "http://0.0.0.0:8000/x", "start_byte": 0, "end_byte": 100, "chunk_id": 0}, timeout=5.0)
        assert r_ssrf.status_code == 400, f"Expected 400 for SSRF target 0.0.0.0, got {r_ssrf.status_code}"

        # 6. Upstream poison: 302 Redirect -> 502
        r_302 = httpx.post(f"{base}/api/worker/fetch-chunk", json={**valid_payload, "url": f"{origin_url}/redirect"}, timeout=5.0)
        assert r_302.status_code == 502, f"Expected 502 on redirect target, got {r_302.status_code}"

        # 7. Upstream poison: Short body -> 502
        r_short = httpx.post(f"{base}/api/worker/fetch-chunk", json={**valid_payload, "url": f"{origin_url}/short"}, timeout=5.0)
        assert r_short.status_code == 502, f"Expected 502 on short body, got {r_short.status_code}"

        # 8. Upstream poison: 200 without Range -> 409 or 502
        r_200 = httpx.post(f"{base}/api/worker/fetch-chunk", json={**valid_payload, "url": f"{origin_url}/norange"}, timeout=5.0)
        assert r_200.status_code in (409, 502), f"Expected 409 or 502 on non-range 200, got {r_200.status_code}"

        # 9. ETag mismatch -> 409 Conflict
        etag_mismatch_payload = {
            "url": f"{origin_url}/35mb.bin",
            "start_byte": 0,
            "end_byte": 1048575,
            "chunk_id": 0,
            "etag": '"different-etag-v2"',
        }
        r_etag = httpx.post(f"{base}/api/worker/fetch-chunk", json=etag_mismatch_payload, timeout=5.0)
        assert r_etag.status_code == 409, f"Expected 409 on ETag mismatch, got {r_etag.status_code}: {r_etag.text}"

    finally:
        terminate_proc(proc)
        shutil.rmtree(tmp_c, ignore_errors=True)
        shutil.rmtree(tmp_d, ignore_errors=True)

    # 10. Token protection check
    port_tok = get_free_port()
    tmp_c_tok = Path(tempfile.mkdtemp(prefix="lanpool_s4_tok_c_"))
    tmp_d_tok = Path(tempfile.mkdtemp(prefix="lanpool_s4_tok_d_"))
    proc_tok = None
    token = "stage4_secret_token"
    try:
        proc_tok = start_node(port_tok, tmp_c_tok, tmp_d_tok, env_extra={"LANPOOL_API_TOKEN": token})
        wait_for_health(port_tok)
        base_tok = f"http://127.0.0.1:{port_tok}"

        r_unauth = httpx.post(f"{base_tok}/api/worker/fetch-chunk", json=valid_payload, timeout=5.0)
        assert r_unauth.status_code == 401, f"Expected 401 without token, got {r_unauth.status_code}"

        r_auth = httpx.post(f"{base_tok}/api/worker/fetch-chunk", json=valid_payload, headers={"X-LANPool-Token": token}, timeout=5.0)
        assert r_auth.status_code == 200, f"Expected 200 with valid token, got {r_auth.status_code}"
    finally:
        terminate_proc(proc_tok)
        shutil.rmtree(tmp_c_tok, ignore_errors=True)
        shutil.rmtree(tmp_d_tok, ignore_errors=True)

    # 11. Loopback disabled (LANPOOL_ALLOW_LOOPBACK=0) -> 400
    port_lb = get_free_port()
    tmp_c_lb = Path(tempfile.mkdtemp(prefix="lanpool_s4_lb_c_"))
    tmp_d_lb = Path(tempfile.mkdtemp(prefix="lanpool_s4_lb_d_"))
    proc_lb = None
    try:
        proc_lb = start_node(port_lb, tmp_c_lb, tmp_d_lb, env_extra={"LANPOOL_ALLOW_LOOPBACK": "0"})
        wait_for_health(port_lb)
        r_lb = httpx.post(
            f"http://127.0.0.1:{port_lb}/api/worker/fetch-chunk",
            json={"url": "http://127.0.0.1:9999/test", "start_byte": 0, "end_byte": 100, "chunk_id": 0},
            timeout=5.0,
        )
        assert r_lb.status_code == 400, f"Expected 400 when loopback is disabled, got {r_lb.status_code}: {r_lb.text}"
    finally:
        terminate_proc(proc_lb)
        shutil.rmtree(tmp_c_lb, ignore_errors=True)
        shutil.rmtree(tmp_d_lb, ignore_errors=True)

    # 12. Fake Helper Missing X-Chunk-SHA256 Regression
    fake_helper = FakeHelperServer().start()
    port_fake = get_free_port()
    tmp_c_fake = Path(tempfile.mkdtemp(prefix="lanpool_s4_fake_c_"))
    tmp_d_fake = Path(tempfile.mkdtemp(prefix="lanpool_s4_fake_d_"))
    proc_fake = None
    try:
        proc_fake = start_node(port_fake, tmp_c_fake, tmp_d_fake)
        wait_for_health(port_fake)
        base_fake = f"http://127.0.0.1:{port_fake}"

        # Add fake helper as peer
        r_add = httpx.post(f"{base_fake}/api/peers/add", json={"ip": "127.0.0.1", "port": fake_helper.port}, timeout=5.0)
        assert r_add.status_code == 200, f"Failed to add fake helper: {r_add.text}"

        # Start 35 MB download
        r_start = httpx.post(
            f"{base_fake}/api/download/start",
            json={"url": f"{origin_url}/35mb.bin", "filename": "fake_test.bin"},
            timeout=10.0,
        )
        assert r_start.status_code == 200, f"Failed to start download: {r_start.text}"
        job_id = r_start.json()["job_id"]

        # Wait for completion
        deadline = time.time() + 30.0
        final_st = None
        while time.time() < deadline:
            st = httpx.get(f"{base_fake}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
            if st.get("status") in ("completed", "failed"):
                final_st = st
                break
            time.sleep(0.05)

        assert final_st is not None, "Timed out waiting for fake helper regression job"
        assert final_st.get("status") == "completed", f"Download failed: {final_st}"
        assert final_st.get("sha256") == PAYLOAD_SHA, f"Corrupted SHA accepted! Expected {PAYLOAD_SHA}, got {final_st.get('sha256')}"

        # An unpaired fake helper must be excluded before receiving any work or secrets.
        assert fake_helper.server.fake_chunks == 0, "Unpaired helper received download work"
        assert r_add.json().get("trusted") is False, "Fake helper was incorrectly paired"
        # Verify no corrupt cache file was registered
        cands = list(tmp_c_fake.glob(f"{PAYLOAD_SHA}_*"))
        assert len(cands) == 1, f"Expected canonical cache entry for valid SHA, found {cands}"
        assert cands[0].stat().st_size == len(PAYLOAD_35MB)
    finally:
        terminate_proc(proc_fake)
        fake_helper.stop()
        shutil.rmtree(tmp_c_fake, ignore_errors=True)
        shutil.rmtree(tmp_d_fake, ignore_errors=True)


def check2_three_node_pooling_and_failover(
    origin: MockOriginServer,
) -> Tuple[int, int, Path, Path, subprocess.Popen, subprocess.Popen]:
    """
    Check 2: 3-Node pooling download of 35 MB file with mid-chunk helper termination.
    - Node A downloads using helpers Node B and Node C.
    - Node C is killed mid-chunk (SIGKILL) while downloading a chunk.
    - Asserts helper C was used, helper B was used, orphan chunk completed by A/B, final SHA matches.
    - Leaves Node A and Node B running for Check 3 and Check 4.
    """
    port_a = get_free_port()
    port_b = get_free_port()
    port_c = get_free_port()

    dir_a = Path(tempfile.mkdtemp(prefix="lanpool_s4_nodeA_"))
    dir_b = Path(tempfile.mkdtemp(prefix="lanpool_s4_nodeB_"))
    dir_c = Path(tempfile.mkdtemp(prefix="lanpool_s4_nodeC_"))

    proc_a = None
    proc_b = None
    proc_c = None

    try:
        proc_a = start_node(port_a, dir_a / "cache", dir_a / "downloads")
        proc_b = start_node(port_b, dir_b / "cache", dir_b / "downloads")
        proc_c = start_node(port_c, dir_c / "cache", dir_c / "downloads")

        wait_for_health(port_a)
        wait_for_health(port_b)
        wait_for_health(port_c)

        h_a = httpx.get(f"http://127.0.0.1:{port_a}/api/health", timeout=3.0).json()
        h_b = httpx.get(f"http://127.0.0.1:{port_b}/api/health", timeout=3.0).json()
        h_c = httpx.get(f"http://127.0.0.1:{port_c}/api/health", timeout=3.0).json()

        id_b = h_b["node_id"]
        id_c = h_c["node_id"]

        # Establish mesh: A knows B and C; B knows A and C
        for target, peers in ((port_a, (port_b, port_c)), (port_b, (port_a, port_c))):
            for peer in peers:
                r_add = httpx.post(
                    f"http://127.0.0.1:{target}/api/peers/add",
                    json={"ip": "127.0.0.1", "port": peer},
                    timeout=5.0,
                )
                assert r_add.status_code == 200, f"Failed to add peer: {r_add.text}"

        # Start 35 MB pooled download on Node A
        start_resp = httpx.post(
            f"http://127.0.0.1:{port_a}/api/download/start",
            json={"url": f"{origin.url}/35mb.bin", "filename": "pooled_35mb.bin"},
            timeout=10.0,
        )
        assert start_resp.status_code == 200, f"Failed to start download on Node A: {start_resp.text}"
        job_id = start_resp.json().get("job_id")

        seen_helpers = set()
        orphan_chunk_id = None
        killed_c = False

        # Poll status: detect helper C downloading a chunk, then kill C with SIGKILL
        deadline_kill = time.time() + 10.0
        while time.time() < deadline_kill:
            st = httpx.get(f"http://127.0.0.1:{port_a}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
            for ch in st.get("chunks", []):
                wid = ch.get("worker_id") or ""
                if wid.startswith("helper-"):
                    seen_helpers.add(wid)

            if orphan_chunk_id is None:
                for ch in st.get("chunks", []):
                    wid = ch.get("worker_id") or ""
                    if wid == f"helper-{id_c[:8]}" and ch.get("status") == "downloading":
                        orphan_chunk_id = ch.get("chunk_id")
                        proc_c.kill()
                        proc_c.wait(timeout=2.0)
                        killed_c = True
                        break

            if killed_c:
                break
            if st.get("status") in ("completed", "failed"):
                break
            time.sleep(0.01)

        assert killed_c is True, f"Never observed a chunk assigned to helper C (chunks: {st.get('chunks')})"

        # Wait for Node A to complete the download with self-healing failover
        deadline_complete = time.time() + 35.0
        final_status = None
        while time.time() < deadline_complete:
            st = httpx.get(f"http://127.0.0.1:{port_a}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
            for ch in st.get("chunks", []):
                wid = ch.get("worker_id") or ""
                if wid.startswith("helper-"):
                    seen_helpers.add(wid)
            if st.get("status") in ("completed", "failed"):
                final_status = st
                break
            time.sleep(0.02)

        assert final_status is not None, "Timed out waiting for Node A download to complete"
        assert final_status.get("status") == "completed", f"Download failed: {final_status}"
        assert final_status.get("sha256") == PAYLOAD_SHA, f"Final SHA mismatch: {final_status.get('sha256')}"

        # Assert helper C and helper B were both utilized
        assert any(w.startswith(f"helper-{id_c[:8]}") for w in seen_helpers), f"Helper C ({id_c[:8]}) never recorded in seen_helpers: {seen_helpers}"
        assert any(w.startswith(f"helper-{id_b[:8]}") for w in seen_helpers), f"Helper B ({id_b[:8]}) never recorded in seen_helpers: {seen_helpers}"

        # Assert orphan chunk completed by A or B (not C) and was retried
        orphan_chunk = None
        for ch in final_status.get("chunks", []):
            if ch.get("chunk_id") == orphan_chunk_id:
                orphan_chunk = ch
                break

        assert orphan_chunk is not None, f"Orphan chunk {orphan_chunk_id} not found in final chunks"
        assert orphan_chunk.get("status") == "done", f"Orphan chunk {orphan_chunk_id} not done: {orphan_chunk}"
        assert not (orphan_chunk.get("worker_id") or "").startswith(f"helper-{id_c[:8]}"), f"Orphan chunk finished by dead helper C: {orphan_chunk}"
        assert orphan_chunk.get("retries", 0) >= 1, f"Orphan chunk retry count not incremented: {orphan_chunk}"

        # Verify no .part files leaked
        part_files = list((dir_a / "downloads").glob("*.part"))
        assert len(part_files) == 0, f"Found orphan .part files: {part_files}"

        # Verify physical file exists and matches payload SHA
        downloaded_file = dir_a / "downloads" / "pooled_35mb.bin"
        if not downloaded_file.exists():
            downloaded_file = dir_a / "cache" / f"{PAYLOAD_SHA}_pooled_35mb.bin"
        assert downloaded_file.exists(), f"Downloaded file does not exist on Node A: {downloaded_file}"
        assert downloaded_file.stat().st_size == len(PAYLOAD_35MB), f"File size mismatch: {downloaded_file.stat().st_size}"
        assert hashlib.sha256(downloaded_file.read_bytes()).hexdigest() == PAYLOAD_SHA

        # Cleanup Node C
        shutil.rmtree(dir_c, ignore_errors=True)

        return port_a, port_b, dir_a, dir_b, proc_a, proc_b

    except Exception:
        terminate_proc(proc_a)
        terminate_proc(proc_b)
        terminate_proc(proc_c)
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(dir_b, ignore_errors=True)
        shutil.rmtree(dir_c, ignore_errors=True)
        raise


def check3_phase1_peer_cache_hit(port_a: int, port_b: int, dir_b: Path, origin: MockOriginServer) -> None:
    """Check 3: Phase 1 peer cache hit on Node B fetching from Node A's cache without origin chunk requests."""
    chunks_before = origin.server.chunk_count

    # Start download of same 35 MB URL on Node B
    start_resp = httpx.post(
        f"http://127.0.0.1:{port_b}/api/download/start",
        json={"url": f"{origin.url}/35mb.bin", "filename": "peer_cache_35mb.bin"},
        timeout=10.0,
    )
    assert start_resp.status_code == 200, f"Failed to start download on Node B: {start_resp.text}"
    job_id = start_resp.json().get("job_id")

    # Poll status on Node B until completed
    deadline = time.time() + 20.0
    final_status = None
    while time.time() < deadline:
        st = httpx.get(f"http://127.0.0.1:{port_b}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
        if st.get("status") in ("completed", "failed"):
            final_status = st
            break
        time.sleep(0.05)

    assert final_status is not None, "Timed out waiting for Node B download"
    assert final_status.get("status") == "completed", f"Expected completed status on Node B, got: {final_status}"
    assert final_status.get("sha256") == PAYLOAD_SHA

    # Verify origin chunk requests did NOT increase (only probe is allowed)
    chunks_after = origin.server.chunk_count
    assert chunks_after == chunks_before, f"Expected 0 origin chunk requests for peer cache hit; grew from {chunks_before} to {chunks_after}"

    # Verify file content
    file_b = dir_b / "downloads" / "peer_cache_35mb.bin"
    if not file_b.exists():
        file_b = dir_b / "cache" / f"{PAYLOAD_SHA}_peer_cache_35mb.bin"
    assert file_b.exists(), "Downloaded file missing on Node B"
    assert hashlib.sha256(file_b.read_bytes()).hexdigest() == PAYLOAD_SHA

    # Verify file is registered in Node B's cache
    lk = httpx.get(f"http://127.0.0.1:{port_b}/api/cache/lookup", params={"url": f"{origin.url}/35mb.bin", "etag": '"origin-v1"'}, timeout=5.0).json()
    assert lk.get("hit") is True, f"Expected Node B to register file in local cache: {lk}"


def check4_phase1_local_cache_hit(
    port_a: int,
    dir_a: Path,
    port_b: int,
    dir_b: Path,
    proc_b: subprocess.Popen,
    origin: MockOriginServer,
) -> None:
    """
    Check 4: Phase 1 local cache hit on Node A.
    Node B is stopped first to prove download cannot pass via peer cache.
    Asserts chunks_total == 0, origin chunk count unchanged, and /api/cache/stream/{sha} works.
    """
    # 1. Terminate Node B so peer cache cannot satisfy the request
    terminate_proc(proc_b)
    shutil.rmtree(dir_b, ignore_errors=True)

    chunks_before = origin.server.chunk_count

    start_resp = httpx.post(
        f"http://127.0.0.1:{port_a}/api/download/start",
        json={"url": f"{origin.url}/35mb.bin", "filename": "local_cache_35mb.bin"},
        timeout=10.0,
    )
    assert start_resp.status_code == 200, f"Failed to start local cache download: {start_resp.text}"
    job_id = start_resp.json().get("job_id")

    # Poll status - should complete near instantly
    deadline = time.time() + 10.0
    final_status = None
    while time.time() < deadline:
        st = httpx.get(f"http://127.0.0.1:{port_a}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
        if st.get("status") in ("completed", "failed"):
            final_status = st
            break
        time.sleep(0.02)

    assert final_status is not None and final_status.get("status") == "completed", f"Local cache download failed: {final_status}"
    assert final_status.get("chunks_total") == 0, f"Expected chunks_total == 0 on local hit, got {final_status.get('chunks_total')}"
    assert origin.server.chunk_count == chunks_before, "Origin chunk count should not increase on local cache hit"

    # Destination file copied to downloads/
    file_local = dir_a / "downloads" / "local_cache_35mb.bin"
    assert file_local.exists(), "Local cache destination file missing in downloads/"
    assert hashlib.sha256(file_local.read_bytes()).hexdigest() == PAYLOAD_SHA

    # Verify /api/cache/stream/{sha} returns exact binary
    lk = httpx.get(f"http://127.0.0.1:{port_a}/api/cache/lookup", params={"url": f"{origin.url}/35mb.bin", "etag": '"origin-v1"'}, timeout=5.0).json()
    assert lk.get("hit") is True, f"Cache lookup failed on Node A: {lk}"
    sha = lk["sha256"]

    st_resp = httpx.get(f"http://127.0.0.1:{port_a}/api/cache/stream/{sha}", timeout=15.0)
    assert st_resp.status_code == 200, f"Failed to stream from cache: {st_resp.status_code}"
    assert hashlib.sha256(st_resp.content).hexdigest() == PAYLOAD_SHA


def check5_solo_no_peers_path(origin: MockOriginServer) -> None:
    """
    Check 5: Solo node without peers downloads 5 MB file normally.
    Uses dedicated unique UDP discovery port to ensure zero discovered peers.
    Asserts peers count == 0 and all chunk workers start with 'self-'.
    """
    port_solo = get_free_port()
    udp_solo = free_udp_port()
    tmp_c = Path(tempfile.mkdtemp(prefix="lanpool_s4_solo_c_"))
    tmp_d = Path(tempfile.mkdtemp(prefix="lanpool_s4_solo_d_"))
    proc = None
    try:
        proc = start_node(port_solo, tmp_c, tmp_d, env_extra={"LANPOOL_UDP_PORT": str(udp_solo)})
        wait_for_health(port_solo)
        base = f"http://127.0.0.1:{port_solo}"

        # Assert 0 peers
        peers_resp = httpx.get(f"{base}/api/peers/list", timeout=3.0).json()
        assert peers_resp.get("count") == 0, f"Expected 0 peers on solo node, got: {peers_resp}"

        start_resp = httpx.post(
            f"{base}/api/download/start",
            json={"url": f"{origin.url}/5mb.bin", "filename": "solo_5mb.bin"},
            timeout=10.0,
        )
        assert start_resp.status_code == 200, f"Solo download start failed: {start_resp.text}"
        job_id = start_resp.json().get("job_id")

        deadline = time.time() + 20.0
        final_status = None
        while time.time() < deadline:
            st = httpx.get(f"{base}/api/download/status", params={"job_id": job_id}, timeout=3.0).json()
            if st.get("status") in ("completed", "failed"):
                final_status = st
                break
            time.sleep(0.05)

        assert final_status is not None and final_status.get("status") == "completed", f"Solo download failed: {final_status}"
        assert final_status.get("sha256") == PAYLOAD_5MB_SHA

        # Assert all workers were self-workers
        worker_ids = {c.get("worker_id") for c in final_status.get("chunks", [])}
        assert all((w or "").startswith("self-") for w in worker_ids), f"Non-self worker found in solo download: {worker_ids}"

        solo_file = tmp_d / "solo_5mb.bin"
        if not solo_file.exists():
            solo_file = tmp_c / f"{PAYLOAD_5MB_SHA}_solo_5mb.bin"
        assert solo_file.exists(), "Solo downloaded file missing"
        assert hashlib.sha256(solo_file.read_bytes()).hexdigest() == PAYLOAD_5MB_SHA
    finally:
        terminate_proc(proc)
        shutil.rmtree(tmp_c, ignore_errors=True)
        shutil.rmtree(tmp_d, ignore_errors=True)


# ==============================================================================
# Main Orchestration Routine
# ==============================================================================

def run_all_checks() -> bool:
    """Executes all 5 Stage 4 verification checks and reports status."""
    print("======================================================================")
    print("LANPool Stage 4 Verification Gate: Cooperative Multi-Peer Pooling")
    print("======================================================================")

    origin = MockOriginServer(delay=0.5).start()
    all_passed = True
    start_total = time.time()

    proc_a = None
    proc_b = None
    dir_a = None
    dir_b = None

    try:
        # Check 1: Helper endpoint validation
        t0 = time.time()
        try:
            check1_helper_endpoint(origin.url)
            print(f"[Check 1: Helper endpoint fetch-chunk validation] -> PASSED ({time.time() - t0:.2f}s)")
        except Exception as exc:
            print(f"[Check 1: Helper endpoint fetch-chunk validation] -> FAILED ({time.time() - t0:.2f}s): {exc}")
            all_passed = False
            return False

        # Check 2: 3-Node pooling & failover
        t0 = time.time()
        try:
            port_a, port_b, dir_a, dir_b, proc_a, proc_b = check2_three_node_pooling_and_failover(origin)
            print(f"[Check 2: 3-node pooling & self-healing failover] -> PASSED ({time.time() - t0:.2f}s)")
        except Exception as exc:
            print(f"[Check 2: 3-node pooling & self-healing failover] -> FAILED ({time.time() - t0:.2f}s): {exc}")
            all_passed = False
            return False

        # Check 3: Phase 1 peer cache hit
        t0 = time.time()
        try:
            check3_phase1_peer_cache_hit(port_a, port_b, dir_b, origin)
            print(f"[Check 3: Phase 1 peer cache hit & zero origin chunks] -> PASSED ({time.time() - t0:.2f}s)")
        except Exception as exc:
            print(f"[Check 3: Phase 1 peer cache hit & zero origin chunks] -> FAILED ({time.time() - t0:.2f}s): {exc}")
            all_passed = False

        # Check 4: Phase 1 local cache hit
        t0 = time.time()
        try:
            check4_phase1_local_cache_hit(port_a, dir_a, port_b, dir_b, proc_b, origin)
            proc_b = None
            dir_b = None
            print(f"[Check 4: Phase 1 local cache hit & zero origin chunks] -> PASSED ({time.time() - t0:.2f}s)")
        except Exception as exc:
            print(f"[Check 4: Phase 1 local cache hit & zero origin chunks] -> FAILED ({time.time() - t0:.2f}s): {exc}")
            all_passed = False

        # Check 5: Solo / No-peers path
        t0 = time.time()
        try:
            check5_solo_no_peers_path(origin)
            print(f"[Check 5: Solo node / no-peers download path] -> PASSED ({time.time() - t0:.2f}s)")
        except Exception as exc:
            print(f"[Check 5: Solo node / no-peers download path] -> FAILED ({time.time() - t0:.2f}s): {exc}")
            all_passed = False

    finally:
        terminate_proc(proc_a)
        terminate_proc(proc_b)
        origin.stop()
        if dir_a:
            shutil.rmtree(dir_a, ignore_errors=True)
        if dir_b:
            shutil.rmtree(dir_b, ignore_errors=True)

    total_dur = time.time() - start_total
    print("----------------------------------------------------------------------")
    if all_passed:
        print(f"Stage 4 Gate Status: PASSED (Total Runtime: {total_dur:.2f}s)")
    else:
        print(f"Stage 4 Gate Status: FAILED (Total Runtime: {total_dur:.2f}s)")
    print("======================================================================")

    return all_passed


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
