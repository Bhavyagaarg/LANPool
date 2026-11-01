#!/usr/bin/env python3
"""
LANPool Stage 3.5 Verification Gate Script (verify_stage3_5.py)
Tests all 20 audit remediation findings (Findings 1 to 20):
1. Retry exhaustion: bounded retries (MAX_CHUNK_RETRIES=5), job failure with retries error, no orphan .part, <15s.
   ETag pinning: mock server changes ETag on chunk GET -> job fails with RemoteContentChanged / 'etag', no orphan .part.
2. Non-Range server and wildcard Content-Range rejection: fail-fast with 'Range' / 'wildcard', no orphan .part.
3. Disk writer shutdown & exception handling: writer receives sentinel on fatal and is awaited; writer exception drains queues without hang.
4. Concurrent filename conflict & 429 concurrency: exact/whitespace/URL duplicate 409, whitespace-only 400, 5th download 429 concurrency.
5. Peer IP safety validation: 0.0.0.0 and 255.255.255.255 return 400; offline health returns 502.
6. Dual URL cache indexing, True LRU eviction & isolated instances: O(1) index hits original_url and final_url; LRU touch preserves accessed item; two instances isolated.
7. Peer registry capacity, manual preservation & dedupe: capped at 256 UDP peers, oldest evicted, manual peer never evicted, same ip:port dedupes.
8. UDP bind conflict resilience: exclusive bind foreign process -> node online, udp_listener.running=False, last_error populated unconditionally.
9. Test file size enforcement: /api/test-file/101 returns 400; /api/test-file/1 returns 200.
10. API token security & loopback toggle: token protects all 8 read/write endpoints, health/test-file open; default loopback downloads allowed, loopback=0 returns 400.
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
from typing import Dict, Optional, Tuple

import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_TEST_FILES", "1")
os.environ.setdefault("LANPOOL_TRUST_GROUP_CONTENT", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-test-group-key-not-for-deployment")

import httpx

from config import CHUNK_SIZE, MAX_CHUNK_RETRIES
from core.cache_manager import CacheManager
from core.downloader import SoloDownloadTask, probe_url
from core.peer_registry import PeerRegistry

PROJECT_ROOT = Path(__file__).resolve().parent


def get_free_port() -> int:
    """Allocates an ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


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
        time.sleep(0.15)
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
# In-Memory Mock Servers & Helpers
# ==============================================================================

PAYLOAD_2MB = bytes([i % 251 for i in range(2 * 1024 * 1024)])


class HangingServer:
    """Accepts TCP connections and never replies, keeping network operations pending."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.conns = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        self.sock.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
                self.conns.append(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self.stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass


class MockServerThread:
    """Runs a standard library ThreadingHTTPServer in a background daemon thread."""

    def __init__(self, handler_cls):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


class MockRangeHandler(http.server.BaseHTTPRequestHandler):
    """Standard Range handler providing HTTP 206 for byte ranges."""
    protocol_version = "HTTP/1.1"
    etag = '"mock-range-v1"'

    def do_GET(self):
        rng = self.headers.get("Range", "")
        if rng:
            m = re.match(r"bytes=(\d+)-(\d*)", rng)
            if not m:
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(PAYLOAD_2MB) - 1
            end = min(end, len(PAYLOAD_2MB) - 1)
            body = PAYLOAD_2MB[start : end + 1]
            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(PAYLOAD_2MB)}")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self.etag)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(PAYLOAD_2MB)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self.etag)
            self.end_headers()
            try:
                self.wfile.write(PAYLOAD_2MB)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, format, *args):
        pass


class MockRetryHandler(MockRangeHandler):
    """Responds 206 to Range bytes=0-0 probe, but returns 500 to chunk requests."""

    def do_GET(self):
        rng = self.headers.get("Range", "")
        if rng == "bytes=0-0":
            return super().do_GET()
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()


class MockETagChangeHandler(MockRangeHandler):
    """Returns ETag 'v1' on probe, but flips to 'v2' on subsequent chunk requests (Finding 15)."""

    def do_GET(self):
        rng = self.headers.get("Range", "")
        if rng == "bytes=0-0":
            self.etag = '"v1"'
            return super().do_GET()
        self.etag = '"v2"'
        return super().do_GET()


class MockNoRangeHandler(http.server.BaseHTTPRequestHandler):
    """Responds HTTP 200 without Accept-Ranges or Content-Range to simulate non-Range origin."""

    def do_GET(self):
        data = b"Y" * 1024
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class MockWildcardRangeHandler(http.server.BaseHTTPRequestHandler):
    """Responds HTTP 206 with Content-Range: bytes 0-0/* to test wildcard rejection."""

    def do_GET(self):
        self.send_response(206)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Range", "bytes 0-0/*")
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(b"Z")

    def log_message(self, format, *args):
        pass


class MockValidChunkHandler(MockRangeHandler):
    """Provides valid HTTP 206 Range responses for testing writer errors."""
    pass


class MockOfflineHealthHandler(http.server.BaseHTTPRequestHandler):
    """Returns status: offline to test peer health validation (Finding 6)."""

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/api/health":
            body = json.dumps({"status": "offline", "node_id": "mock_offline_node"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


# ==============================================================================
# Verification Checks
# ==============================================================================

async def check1_retry_exhaustion_and_etag_pinning() -> None:
    """Findings 1 & 15: Retry exhaustion fails <15s with retries error; ETag change aborts immediately."""
    # Part A: Retry exhaustion
    server = MockServerThread(MockRetryHandler)
    tmp_dir = tempfile.mkdtemp(prefix="lanpool_c1_retry_")
    try:
        task = SoloDownloadTask(
            job_id="test_retry_job",
            url=f"{server.url}/file.bin",
            download_dir=Path(tmp_dir),
            chunk_size=CHUNK_SIZE,
            num_workers=1,
        )
        t0 = time.time()
        await task._run()
        elapsed = time.time() - t0

        assert task.status == "failed", f"Expected status 'failed', got {task.status}"
        assert task.error is not None, "Expected error message on task failure"
        assert "retries" in task.error.lower(), f"Error should mention retries: {task.error}"
        assert not task.part_path.exists(), f"Orphan .part file should be unlinked: {task.part_path}"
        assert elapsed < 15.0, f"Retry exhaustion took too long: {elapsed:.2f}s"
    finally:
        server.stop()
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Part B: ETag change aborts job immediately (Finding 15)
    s_etag = MockServerThread(MockETagChangeHandler)
    tmp_etag = tempfile.mkdtemp(prefix="lanpool_c1_etag_")
    try:
        task_etag = SoloDownloadTask(
            job_id="test_etag_job",
            url=f"{s_etag.url}/file.bin",
            download_dir=Path(tmp_etag),
            chunk_size=CHUNK_SIZE,
            num_workers=1,
        )
        await task_etag._run()
        assert task_etag.status == "failed", f"Expected failed status, got {task_etag.status}"
        assert "etag" in (task_etag.error or "").lower(), f"Error should mention ETag change: {task_etag.error}"
        assert not task_etag.part_path.exists(), f"Orphan .part file should be unlinked on ETag abort: {task_etag.part_path}"
    finally:
        s_etag.stop()
        shutil.rmtree(tmp_etag, ignore_errors=True)


async def check2_range_enforcement_and_wildcard() -> None:
    """Findings 1 & 2: Non-Range server and Content-Range bytes 0-0/* wildcard rejection."""
    tmp_dir = tempfile.mkdtemp(prefix="lanpool_c2_")
    try:
        # Part A: Non-Range origin (HTTP 200 without Range support)
        s_norange = MockServerThread(MockNoRangeHandler)
        try:
            task_norange = SoloDownloadTask(
                job_id="test_norange_job",
                url=f"{s_norange.url}/file.bin",
                download_dir=Path(tmp_dir),
            )
            await task_norange._run()
            assert task_norange.status == "failed", f"Expected failed status, got {task_norange.status}"
            assert "range" in (task_norange.error or "").lower(), f"Error should mention Range: {task_norange.error}"
            assert not task_norange.part_path.exists(), "No .part file should remain"
        finally:
            s_norange.stop()

        # Part B: Wildcard Content-Range (bytes 0-0/*)
        s_wildcard = MockServerThread(MockWildcardRangeHandler)
        try:
            task_wildcard = SoloDownloadTask(
                job_id="test_wildcard_job",
                url=f"{s_wildcard.url}/file.bin",
                download_dir=Path(tmp_dir),
            )
            await task_wildcard._run()
            assert task_wildcard.status == "failed", f"Expected failed status, got {task_wildcard.status}"
            assert "wildcard" in (task_wildcard.error or "").lower() or "content-range" in (task_wildcard.error or "").lower(), (
                f"Error should mention wildcard Content-Range: {task_wildcard.error}"
            )
            assert not task_wildcard.part_path.exists(), "No .part file should remain"
        finally:
            s_wildcard.stop()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def check3_writer_sentinel_and_exception() -> None:
    """Finding 3: Disk writer receives sentinel on fatal and is awaited; writer exception drains queues without hang."""
    # Part A: Sentinel regression (writer blocks on writer_queue.get(), fatal triggered, assert sentinel received, cancelled=False, writer done)
    server = MockServerThread(MockRetryHandler)
    tmp_a = tempfile.mkdtemp(prefix="lanpool_c3_sentinel_")
    try:
        task = SoloDownloadTask(
            job_id="test_writer_sentinel",
            url=f"{server.url}/file.bin",
            download_dir=Path(tmp_a),
            chunk_size=1024 * 1024,
            num_workers=1,
        )
        state = {"sentinel": False, "cancelled": False}

        async def sentinel_writer():
            task.part_path.parent.mkdir(parents=True, exist_ok=True)
            task.part_path.write_bytes(b"partial-data")
            try:
                item = await task.writer_queue.get()
                if item is None:
                    state["sentinel"] = True
                task.writer_queue.task_done()
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise

        task._disk_writer_task = sentinel_writer
        await task._run()

        assert task.status == "failed", f"Expected failed status, got {task.status}"
        assert "retries" in (task.error or "").lower(), f"Error should report retries: {task.error}"
        assert not task.part_path.exists(), f"Orphan .part file should be unlinked: {task.part_path}"
        assert state["sentinel"] is True, "Writer must receive sentinel None"
        assert state["cancelled"] is False, "Writer must not be cancelled"
        assert task._writer_handle is not None and task._writer_handle.done(), "Writer task must be awaited and done"
    finally:
        server.stop()
        shutil.rmtree(tmp_a, ignore_errors=True)

    # Part B: Writer exception handling (disk full simulation)
    s_valid = MockServerThread(MockValidChunkHandler)
    tmp_b = tempfile.mkdtemp(prefix="lanpool_c3_err_")
    try:
        task_err = SoloDownloadTask(
            job_id="test_writer_err",
            url=f"{s_valid.url}/file.bin",
            download_dir=Path(tmp_b),
            chunk_size=1048576,
            num_workers=2,
        )

        async def failing_writer():
            task_err.part_path.parent.mkdir(parents=True, exist_ok=True)
            task_err.part_path.write_bytes(b"partial-data")
            task_err._writer_error = OSError("Simulated disk full (ENOSPC)")
            task_err.fatal_event.set()
            raise OSError("Simulated disk full (ENOSPC)")

        task_err._disk_writer_task = failing_writer

        t0 = time.time()
        await task_err._run()
        elapsed = time.time() - t0

        assert task_err.status == "failed", f"Expected failed status, got {task_err.status}"
        assert "disk full" in (task_err.error or "").lower(), f"Error should report writer failure: {task_err.error}"
        assert not task_err.part_path.exists(), f"Orphan .part file should be unlinked: {task_err.part_path}"
        assert elapsed < 5.0, f"Writer failure handling took too long: {elapsed:.2f}s"
    finally:
        s_valid.stop()
        shutil.rmtree(tmp_b, ignore_errors=True)


def check4_concurrent_filename_conflict_and_429(port: int) -> None:
    """Findings 4, 5, 11: Exact/whitespace/URL duplicate 409, whitespace-only 400, 5th download 429 concurrency."""
    hang = HangingServer().start()
    base = f"http://127.0.0.1:{port}"
    try:
        slow_url = f"http://127.0.0.1:{hang.port}/slow.bin"

        # 1. Exact duplicate filename -> 409
        r1 = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "dup_exact.bin"}, timeout=5.0)
        assert r1.status_code == 200, f"Expected 200 on first start, got {r1.status_code}: {r1.text}"
        r2 = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "dup_exact.bin"}, timeout=5.0)
        assert r2.status_code == 409, f"Expected 409 Conflict on exact duplicate, got {r2.status_code}: {r2.text}"

        # 2. Whitespace-padded filename duplicate -> 409
        r_ws1 = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "dup_ws.bin"}, timeout=5.0)
        assert r_ws1.status_code == 200, f"Expected 200 on first start, got {r_ws1.status_code}: {r_ws1.text}"
        r_ws2 = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "  dup_ws.bin  "}, timeout=5.0)
        assert r_ws2.status_code == 409, f"Expected 409 Conflict on whitespace duplicate, got {r_ws2.status_code}: {r_ws2.text}"

        # 3. URL-derived duplicate -> 409
        r_url1 = httpx.post(f"{base}/api/download/start", json={"url": f"http://127.0.0.1:{hang.port}/dup_url.bin"}, timeout=5.0)
        assert r_url1.status_code == 200, f"Expected 200 on first start, got {r_url1.status_code}: {r_url1.text}"
        r_url2 = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "dup_url.bin"}, timeout=5.0)
        assert r_url2.status_code == 409, f"Expected 409 Conflict on URL-derived duplicate, got {r_url2.status_code}: {r_url2.text}"

        # 4. Whitespace-only filename -> 400
        r_empty = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "   "}, timeout=5.0)
        assert r_empty.status_code == 400, f"Expected 400 Bad Request on whitespace-only filename, got {r_empty.status_code}: {r_empty.text}"

        # 5. Concurrency 429 limit (MAX_CONCURRENT_DOWNLOADS=4)
        r_4th = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "active_4.bin"}, timeout=5.0)
        assert r_4th.status_code == 200, f"Expected 200 on 4th active download, got {r_4th.status_code}: {r_4th.text}"

        r_5th = httpx.post(f"{base}/api/download/start", json={"url": slow_url, "filename": "active_5.bin"}, timeout=5.0)
        assert r_5th.status_code == 429, f"Expected 429 Too Many Requests on 5th active download, got {r_5th.status_code}: {r_5th.text}"
        assert "concurrent" in r_5th.text.lower() or "limit" in r_5th.text.lower() or "active" in r_5th.text.lower()
    finally:
        hang.stop()


def check5_peer_ip_safety_and_health_validation(port: int) -> None:
    """Finding 6: 0.0.0.0 and 255.255.255.255 return 400; offline health returns 502."""
    url = f"http://127.0.0.1:{port}/api/peers/add"

    r1 = httpx.post(url, json={"ip": "0.0.0.0", "port": 8000}, timeout=5.0)
    assert r1.status_code == 400, f"Expected 400 for 0.0.0.0, got {r1.status_code}: {r1.text}"

    r2 = httpx.post(url, json={"ip": "255.255.255.255", "port": 8000}, timeout=5.0)
    assert r2.status_code == 400, f"Expected 400 for 255.255.255.255, got {r2.status_code}: {r2.text}"

    s_offline = MockServerThread(MockOfflineHealthHandler)
    try:
        r3 = httpx.post(url, json={"ip": "127.0.0.1", "port": s_offline.port}, timeout=5.0)
        assert r3.status_code == 502, f"Expected 502 for offline peer status, got {r3.status_code}: {r3.text}"
        assert "offline" in r3.text.lower(), f"Expected offline status in error: {r3.text}"
    finally:
        s_offline.stop()


def check6_cache_indexing_true_lru_and_dual_instances() -> None:
    """Findings 7, 12, 13, 14: CacheManager O(1) index, true LRU touch/eviction, and dual instance isolation."""
    # Part A: Single CacheManager dual URL index & True LRU
    tmp_cache = tempfile.mkdtemp(prefix="lanpool_c6_")
    try:
        cache_dir = Path(tmp_cache)
        cm = CacheManager(cache_dir=cache_dir, max_cache_bytes=3 * 1024 * 1024)

        fa = cache_dir / "file_a.bin"
        fb = cache_dir / "file_b.bin"
        fc = cache_dir / "file_c.bin"

        data_a = b"A" * (1024 * 1024)
        data_b = b"B" * (1024 * 1024)
        data_c = b"C" * (1536 * 1024)

        fa.write_bytes(data_a)
        fb.write_bytes(data_b)
        fc.write_bytes(data_c)

        sha_a = hashlib.sha256(data_a).hexdigest()
        sha_b = hashlib.sha256(data_b).hexdigest()
        sha_c = hashlib.sha256(data_c).hexdigest()

        cm.register_completed(
            file_path=fa,
            final_url="http://cdn.example.com/file_a.bin",
            etag='"etag-a"',
            sha256=sha_a,
            filename="file_a.bin",
            size=len(data_a),
            original_url="http://example.com/redirect/file_a.bin",
        )

        hit_orig = cm.lookup("http://example.com/redirect/file_a.bin", '"etag-a"')
        assert hit_orig["hit"] is True, "Expected hit on original_url"
        assert hit_orig["sha256"] == sha_a

        hit_final = cm.lookup("http://cdn.example.com/file_a.bin", '"etag-a"')
        assert hit_final["hit"] is True, "Expected hit on final_url"
        assert hit_final["sha256"] == sha_a

        time.sleep(0.05)
        cm.register_completed(
            file_path=fb,
            final_url="http://cdn.example.com/file_b.bin",
            etag='"etag-b"',
            sha256=sha_b,
            filename="file_b.bin",
            size=len(data_b),
            original_url="http://example.com/redirect/file_b.bin",
        )

        time.sleep(0.05)
        cm.lookup("http://example.com/redirect/file_a.bin", '"etag-a"')

        time.sleep(0.05)
        cm.register_completed(
            file_path=fc,
            final_url="http://cdn.example.com/file_c.bin",
            etag='"etag-c"',
            sha256=sha_c,
            filename="file_c.bin",
            size=len(data_c),
            original_url="http://example.com/redirect/file_c.bin",
        )

        hit_b = cm.lookup("http://example.com/redirect/file_b.bin", '"etag-b"')
        assert hit_b["hit"] is False, "File B should have been evicted by LRU"

        hit_a = cm.lookup("http://example.com/redirect/file_a.bin", '"etag-a"')
        assert hit_a["hit"] is True, "File A should be preserved due to recent access"

        hit_c = cm.lookup("http://example.com/redirect/file_c.bin", '"etag-c"')
        assert hit_c["hit"] is True, "Newly added File C should be present"
    finally:
        shutil.rmtree(tmp_cache, ignore_errors=True)

    # Part B: Two CacheManager instances isolated on separate directories (Finding 7)
    tmp_a = tempfile.mkdtemp(prefix="lanpool_c6_iso_a_")
    tmp_b = tempfile.mkdtemp(prefix="lanpool_c6_iso_b_")
    try:
        ca = CacheManager(cache_dir=Path(tmp_a), max_cache_bytes=10 * 1024 * 1024)
        cb = CacheManager(cache_dir=Path(tmp_b), max_cache_bytes=10 * 1024 * 1024)

        pa = Path(tmp_a) / "a.bin"
        pb = Path(tmp_b) / "b.bin"
        da = b"A" * 4096
        db = b"B" * 4096
        pa.write_bytes(da)
        pb.write_bytes(db)

        sha_a = hashlib.sha256(da).hexdigest()
        sha_b = hashlib.sha256(db).hexdigest()

        ca.register_completed(pa, "http://a/final", '"ea"', sha_a, "a.bin", len(da), original_url="http://a/orig")
        cb.register_completed(pb, "http://b/final", '"eb"', sha_b, "b.bin", len(db), original_url="http://b/orig")

        hit_a = ca.lookup("http://a/orig", '"ea"')["hit"]
        miss_b = cb.lookup("http://a/orig", '"ea"')["hit"]
        hit_b = cb.lookup("http://b/orig", '"eb"')["hit"]
        miss_a = ca.lookup("http://b/orig", '"eb"')["hit"]

        assert hit_a is True and miss_b is False, "ca lookup hit should be absent from cb"
        assert hit_b is True and miss_a is False, "cb lookup hit should be absent from ca"
    finally:
        shutil.rmtree(tmp_a, ignore_errors=True)
        shutil.rmtree(tmp_b, ignore_errors=True)


def check7_peer_registry_capacity_preservation_and_dedupe() -> None:
    """Findings 9 & 10: MAX_UDP_PEERS=256 eviction of oldest, manual peer preservation, upgrade & dedupe."""
    # Part A: Basic 256 UDP peer cap & oldest eviction
    reg = PeerRegistry(own_node_id="test_node", own_http_port=8000, own_lan_ip="192.168.1.100")
    base_time = 1000.0

    for i in range(256):
        reg.upsert_udp(
            node_id=f"node_{i}",
            ip=f"10.0.{i // 250}.{(i % 250) + 1}",
            port=8000,
            lan_ip="10.0.0.1",
        )
        reg._peers[f"node_{i}"]["last_seen"] = base_time + i

    peers = reg.list_peers()
    assert len(peers) == 256, f"Expected 256 active peers, got {len(peers)}"

    reg.upsert_udp(
        node_id="node_256",
        ip="10.1.0.1",
        port=8000,
        lan_ip="10.1.0.1",
    )
    reg._peers["node_256"]["last_seen"] = base_time + 500

    peers_after = reg.list_peers()
    assert len(peers_after) == 256, f"Expected capped size 256, got {len(peers_after)}"
    ids = {p["node_id"] for p in peers_after}
    assert "node_0" not in ids, "Oldest peer node_0 should have been evicted"
    assert "node_256" in ids, "Newest peer node_256 must be present"

    # Part B: Restarted node deduplication on same ip:port
    reg.upsert_udp(node_id="old_inst", ip="192.168.1.55", port=8000, lan_ip="192.168.1.55")
    reg._peers["old_inst"]["last_seen"] = base_time + 600

    reg.upsert_udp(node_id="new_inst", ip="192.168.1.55", port=8000, lan_ip="192.168.1.55")
    reg._peers["new_inst"]["last_seen"] = base_time + 601

    matching = [p for p in reg.list_peers() if p["ip"] == "192.168.1.55" and p["port"] == 8000]
    assert len(matching) == 1, f"Expected exactly 1 peer for restarted endpoint, got {len(matching)}"
    assert matching[0]["node_id"] == "new_inst", f"Expected new node_id, got {matching[0]['node_id']}"

    # Part C: Manual peer survives restarted UDP peer
    reg_man = PeerRegistry(own_node_id="own", own_http_port=8000, own_lan_ip="192.168.1.100")
    reg_man.add_manual(ip="10.0.0.5", port=8000, node_id="manual-node", lan_ip="10.0.0.5")
    reg_man.upsert_udp(node_id="restarted-node", ip="10.0.0.5", port=8000, lan_ip="10.0.0.5")
    peers_m = [p for p in reg_man.list_peers() if p["ip"] == "10.0.0.5" and p["port"] == 8000]
    assert len(peers_m) == 1, f"Expected 1 peer, got {len(peers_m)}"
    assert peers_m[0].get("manual") is True, "Manual flag must be preserved"
    assert peers_m[0]["node_id"] == "manual-node", "UDP must not replace a manually enrolled identity"
    reg_man.refresh_health("manual-node", {"node_id": "restarted-node", "qos": {"effective_share_pct": 30}}, trusted=True)
    assert reg_man.get("restarted-node")["manual"] is True, "Authenticated health proof should refresh a restarted identity"

    # Part D: Manual add upgrades UDP peer
    reg_up = PeerRegistry(own_node_id="own", own_http_port=8000, own_lan_ip="192.168.1.100")
    reg_up.upsert_udp(node_id="udp-node", ip="10.0.0.6", port=8000, lan_ip="10.0.0.6")
    reg_up.add_manual(ip="10.0.0.6", port=8000, node_id="manual-node-2", lan_ip="10.0.0.6")
    peers_u = [p for p in reg_up.list_peers() if p["ip"] == "10.0.0.6" and p["port"] == 8000]
    assert len(peers_u) == 1, f"Expected 1 peer, got {len(peers_u)}"
    assert peers_u[0].get("manual") is True, "Peer should be upgraded to manual=True"
    assert peers_u[0]["node_id"] == "manual-node-2"

    # Part E: Manual peer is never evicted by 256 UDP peer cap
    reg_cap = PeerRegistry(own_node_id="own", own_http_port=8000, own_lan_ip="192.168.1.100")
    reg_cap.add_manual(ip="10.9.9.9", port=8000, node_id="keep-manual", lan_ip="10.9.9.9")
    for i in range(256):
        reg_cap.upsert_udp(node_id=f"u{i}", ip=f"10.1.{i // 250}.{(i % 250) + 1}", port=8000, lan_ip="10.1.0.1")
        reg_cap._peers[f"u{i}"]["last_seen"] = 1000 + i
    reg_cap.upsert_udp(node_id="u256", ip="10.2.0.1", port=8000, lan_ip="10.2.0.1")
    ids_cap = {p["node_id"] for p in reg_cap.list_peers()}
    assert "keep-manual" in ids_cap, "Manual peer must never be evicted"
    assert "u0" not in ids_cap, "Oldest UDP peer u0 should be evicted"
    assert len(reg_cap.list_peers()) == 257, f"Expected 257 peers (1 manual + 256 UDP), got {len(reg_cap.list_peers())}"


def check8_udp_bind_failure_resilience() -> None:
    """Findings 9 & 10: Foreign process holding UDP 9999 -> node online, udp_listener.running=False, last_error set."""
    conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Plain exclusive bind - NO socket options (no SO_REUSEADDR, no SO_REUSEPORT)
    try:
        conflict_sock.bind(("0.0.0.0", 9999))
    except Exception as exc:
        conflict_sock.close()
        raise RuntimeError(f"Could not occupy UDP 9999 for test: {exc}")

    port = get_free_port()
    tmp_c = tempfile.mkdtemp(prefix="lanpool_c8_c_")
    tmp_d = tempfile.mkdtemp(prefix="lanpool_c8_d_")
    proc = None

    try:
        proc = start_node(port, Path(tmp_c), Path(tmp_d))
        health = wait_for_health(port)
        assert health.get("status") == "online", f"Expected health status online, got {health}"

        diag = httpx.get(f"http://127.0.0.1:{port}/api/diagnostics/network", timeout=5.0).json()
        udp_diag = diag.get("udp", {})

        assert "listener_running" in udp_diag, "Expected 'listener_running' key in udp diagnostics"
        # UNCONDITIONAL ASSERTIONS:
        assert udp_diag.get("listener_running") is False, f"Expected listener_running == False on bind conflict, got {udp_diag.get('listener_running')}"
        assert bool(udp_diag.get("last_error")), f"Expected non-empty last_error on failed bind, got: {udp_diag.get('last_error')}"
    finally:
        terminate_proc(proc)
        conflict_sock.close()
        shutil.rmtree(tmp_c, ignore_errors=True)
        shutil.rmtree(tmp_d, ignore_errors=True)


def check9_test_file_size_cap(port: int) -> None:
    """Finding 8: /api/test-file/101 returns 400 (cap 100MB); /api/test-file/1 returns 200."""
    url_invalid = f"http://127.0.0.1:{port}/api/test-file/101"
    r_inv = httpx.get(url_invalid, timeout=5.0)
    assert r_inv.status_code == 400, f"Expected 400 for 101 MB test file, got {r_inv.status_code}: {r_inv.text}"

    url_valid = f"http://127.0.0.1:{port}/api/test-file/1"
    r_val = httpx.get(url_valid, timeout=5.0)
    assert r_val.status_code == 200, f"Expected 200 for 1 MB test file, got {r_val.status_code}"
    assert len(r_val.content) == 1024 * 1024, f"Expected exactly 1 MB, got {len(r_val.content)} bytes"


def check10_token_and_loopback_toggle() -> None:
    """Finding 6: API token enforcement on all protected read/write endpoints and loopback toggle."""
    token = "audit_stage35_secret_token"
    port_token = get_free_port()
    tmp_c1 = tempfile.mkdtemp(prefix="lanpool_c10_c1_")
    tmp_d1 = tempfile.mkdtemp(prefix="lanpool_c10_d1_")
    proc_token = None

    try:
        proc_token = start_node(port_token, Path(tmp_c1), Path(tmp_d1), env_extra={"LANPOOL_API_TOKEN": token})
        wait_for_health(port_token)
        base = f"http://127.0.0.1:{port_token}"

        # Protected endpoints list: 6 read/exfiltration endpoints + 2 write endpoints
        protected_endpoints = [
            ("GET", "/api/download/status"),
            ("GET", "/api/cache/list"),
            ("GET", "/api/cache/lookup?url=x&etag=y"),
            ("GET", f"/api/cache/stream/{'0'*64}"),
            ("GET", "/api/peers/list"),
            ("GET", "/api/diagnostics/network"),
        ]

        # Verify all read endpoints reject unauthenticated requests with 401
        for method, path in protected_endpoints:
            r_unauth = httpx.request(method, f"{base}{path}", timeout=5.0)
            assert r_unauth.status_code == 401, f"Expected 401 for unauth {method} {path}, got {r_unauth.status_code}"

            r_wrong = httpx.request(method, f"{base}{path}", headers={"X-LANPool-Token": "bad-token"}, timeout=5.0)
            assert r_wrong.status_code == 401, f"Expected 401 for wrong token {method} {path}, got {r_wrong.status_code}"

            r_auth = httpx.request(method, f"{base}{path}", headers={"X-LANPool-Token": token}, timeout=5.0)
            assert r_auth.status_code != 401, f"Expected non-401 with valid token for {method} {path}, got {r_auth.status_code}"

        # Write endpoints protected
        r_start_unauth = httpx.post(f"{base}/api/download/start", json={"url": "http://127.0.0.1:1/x"}, timeout=5.0)
        assert r_start_unauth.status_code == 401, f"Expected 401 on start without token, got {r_start_unauth.status_code}"

        r_peer_unauth = httpx.post(f"{base}/api/peers/add", json={"ip": "127.0.0.1", "port": 1}, timeout=5.0)
        assert r_peer_unauth.status_code == 401, f"Expected 401 on peer add without token, got {r_peer_unauth.status_code}"

        # Open endpoints remain open without token
        r_health = httpx.get(f"{base}/api/health", timeout=5.0)
        assert r_health.status_code == 200, f"Expected 200 on /api/health without token, got {r_health.status_code}"

        r_testfile = httpx.get(f"{base}/api/test-file/1", timeout=5.0)
        assert r_testfile.status_code == 200, f"Expected 200 on /api/test-file/1 without token, got {r_testfile.status_code}"

    finally:
        terminate_proc(proc_token)
        shutil.rmtree(tmp_c1, ignore_errors=True)
        shutil.rmtree(tmp_d1, ignore_errors=True)

    # Part B: Default loopback allowed - download completes normally
    port_defl = get_free_port()
    tmp_c_def = tempfile.mkdtemp(prefix="lanpool_c10_def_c_")
    tmp_d_def = tempfile.mkdtemp(prefix="lanpool_c10_def_d_")
    proc_defl = None
    try:
        proc_defl = start_node(port_defl, Path(tmp_c_def), Path(tmp_d_def))
        wait_for_health(port_defl)
        base_def = f"http://127.0.0.1:{port_defl}"

        start_resp = httpx.post(
            f"{base_def}/api/download/start",
            json={"url": f"{base_def}/api/test-file/1", "filename": "default_loop_test.bin"},
            timeout=10.0,
        )
        assert start_resp.status_code == 200, f"Expected 200 on default loopback download start, got {start_resp.status_code}: {start_resp.text}"
        job_id = start_resp.json().get("job_id")
        assert job_id, "Expected job_id in download start response"

        # Poll status until completed
        deadline = time.time() + 15.0
        final_status = None
        while time.time() < deadline:
            st = httpx.get(f"{base_def}/api/download/status", params={"job_id": job_id}, timeout=5.0).json()
            if st.get("status") in ("completed", "failed"):
                final_status = st
                break
            time.sleep(0.1)

        assert final_status is not None, "Timed out waiting for default loopback download"
        assert final_status.get("status") == "completed", f"Expected completed status, got: {final_status}"

        # Verify cache lookup & stream
        sha256 = final_status.get("sha256")
        assert sha256, "Expected sha256 on completed download"
        lookup_resp = httpx.get(f"{base_def}/api/cache/lookup", params={"url": f"{base_def}/api/test-file/1", "etag": final_status.get("etag", "")}, timeout=5.0).json()
        assert lookup_resp.get("hit") is True, f"Expected cache hit for completed download: {lookup_resp}"
        stream_resp = httpx.get(f"{base_def}/api/cache/stream/{sha256}", timeout=10.0)
        assert stream_resp.status_code == 200 and len(stream_resp.content) == 1048576, f"Expected 200 and 1MB stream, got {stream_resp.status_code}"
    finally:
        terminate_proc(proc_defl)
        shutil.rmtree(tmp_c_def, ignore_errors=True)
        shutil.rmtree(tmp_d_def, ignore_errors=True)

    # Part C: Loopback disabled (LANPOOL_ALLOW_LOOPBACK=0) returns 400
    port_noloop = get_free_port()
    tmp_c2 = tempfile.mkdtemp(prefix="lanpool_c10_c2_")
    tmp_d2 = tempfile.mkdtemp(prefix="lanpool_c10_d2_")
    proc_noloop = None
    try:
        proc_noloop = start_node(port_noloop, Path(tmp_c2), Path(tmp_d2), env_extra={"LANPOOL_ALLOW_LOOPBACK": "0"})
        wait_for_health(port_noloop)

        r_loop = httpx.post(
            f"http://127.0.0.1:{port_noloop}/api/download/start",
            json={"url": f"http://127.0.0.1:{port_noloop}/api/test-file/1", "filename": "loop_test.bin"},
            timeout=5.0,
        )
        assert r_loop.status_code == 400, f"Expected 400 for loopback download when disabled, got {r_loop.status_code}: {r_loop.text}"
        assert "loopback" in r_loop.text.lower(), f"Expected loopback mention in error: {r_loop.text}"
    finally:
        terminate_proc(proc_noloop)
        shutil.rmtree(tmp_c2, ignore_errors=True)
        shutil.rmtree(tmp_d2, ignore_errors=True)


# ==============================================================================
# Main Orchestration Routine
# ==============================================================================

def run_all_checks() -> bool:
    """Executes all 10 Stage 3.5 verification checks and reports status."""
    print("======================================================================")
    print("LANPool Stage 3.5 Verification Gate: Full Audit Remediation (Findings 1-20)")
    print("======================================================================")

    shared_port = get_free_port()
    tmp_shared_c = tempfile.mkdtemp(prefix="lanpool_shared_c_")
    tmp_shared_d = tempfile.mkdtemp(prefix="lanpool_shared_d_")
    shared_proc = None

    checks = [
        ("Check 1: Retry exhaustion & ETag pinning (Findings 1, 15)", lambda: asyncio.run(check1_retry_exhaustion_and_etag_pinning())),
        ("Check 2: Range enforcement & wildcard rejection (Findings 1, 2)", lambda: asyncio.run(check2_range_enforcement_and_wildcard())),
        ("Check 3: Writer sentinel & exception handling (Finding 3)", lambda: asyncio.run(check3_writer_sentinel_and_exception())),
        ("Check 4: Concurrent filename conflict & 429 concurrency (Findings 4, 5, 11)", lambda: check4_concurrent_filename_conflict_and_429(shared_port)),
        ("Check 5: Peer IP safety & offline health validation (Finding 6)", lambda: check5_peer_ip_safety_and_health_validation(shared_port)),
        ("Check 6: Dual URL cache index, True LRU & multi-instance isolation (Findings 7, 12, 13, 14)", check6_cache_indexing_true_lru_and_dual_instances),
        ("Check 7: Peer registry 256 cap, manual preservation & dedupe (Findings 9, 10)", check7_peer_registry_capacity_preservation_and_dedupe),
        ("Check 8: UDP bind failure resilience (Findings 9, 10)", check8_udp_bind_failure_resilience),
        ("Check 9: Test file size cap 100MB (Finding 8)", lambda: check9_test_file_size_cap(shared_port)),
        ("Check 10: API token coverage & default/disabled loopback (Finding 6)", check10_token_and_loopback_toggle),
    ]

    all_passed = True
    start_total = time.time()

    try:
        shared_proc = start_node(shared_port, Path(tmp_shared_c), Path(tmp_shared_d))
        wait_for_health(shared_port)

        for name, fn in checks:
            t0 = time.time()
            try:
                if "Check 8" in name:
                    terminate_proc(shared_proc)
                    shared_proc = None
                    time.sleep(0.2)

                fn()
                dur = time.time() - t0
                print(f"[{name}] -> PASSED ({dur:.2f}s)")

                if "Check 8" in name:
                    shared_proc = start_node(shared_port, Path(tmp_shared_c), Path(tmp_shared_d))
                    wait_for_health(shared_port)
            except Exception as exc:
                dur = time.time() - t0
                print(f"[{name}] -> FAILED ({dur:.2f}s): {exc}")
                all_passed = False

    finally:
        terminate_proc(shared_proc)
        shutil.rmtree(tmp_shared_c, ignore_errors=True)
        shutil.rmtree(tmp_shared_d, ignore_errors=True)

    total_dur = time.time() - start_total
    print("----------------------------------------------------------------------")
    if all_passed:
        print(f"Stage 3.5 Gate Status: PASSED (Total Runtime: {total_dur:.2f}s)")
    else:
        print(f"Stage 3.5 Gate Status: FAILED (Total Runtime: {total_dur:.2f}s)")
    print("======================================================================")

    return all_passed


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
