#!/usr/bin/env python3
"""
LANPool Stage 1 Verification Gate Script
Tests:
1. Live FastAPI server communication (/api/health, /api/test-file/35)
2. Slicing 35 MB into exactly 4 chunks: #0..#3 (10MB, 10MB, 10MB, 5MB)
3. Chunk status transitions (queued -> downloading -> done)
4. SHA-256 integrity: SHA-256(downloaded file) == SHA-256(served test bytes)
5. Runtime Single-Writer Proof: instruments file operations to prove only the dedicated writer task touches <filename>.part
6. Safeguard #4: Poison assertion on non-206 responses
7. Safeguard #10: Free disk space assertion
"""

import asyncio
import builtins
import hashlib
import sys
import time
from typing import Dict, List, Set

import httpx

from config import CACHE_DIR, CHUNK_SIZE, DEFAULT_PORT, DOWNLOAD_DIR
from core.downloader import SoloDownloadTask, compute_file_sha256
from core.net_utils import check_disk_space
from core.test_data import get_deterministic_data


class FileWriterMonitor:
    """Instruments file operations to record task names opening/writing to .part files."""
    def __init__(self):
        self.original_open = builtins.open
        self.writers_by_file: Dict[str, Set[str]] = {}
        self.write_events: List[dict] = []

    def start(self):
        builtins.open = self._monitored_open

    def stop(self):
        builtins.open = self.original_open

    def _monitored_open(self, file, mode="r", *args, **kwargs):
        filepath = str(file)
        if filepath.endswith(".part"):
            try:
                task = asyncio.current_task()
                task_name = task.get_name() if task else "non-async-context"
            except Exception:
                task_name = "unknown"

            if filepath not in self.writers_by_file:
                self.writers_by_file[filepath] = set()
            self.writers_by_file[filepath].add(task_name)
            self.write_events.append({
                "file": filepath,
                "mode": mode,
                "task": task_name,
                "time": time.time()
            })

        return self.original_open(file, mode, *args, **kwargs)


async def run_verification(server_url: str = "http://127.0.0.1:8000"):
    print("=" * 70)
    print("LANPool STAGE 1 VERIFICATION GATE")
    print(f"Target Server: {server_url}")
    print("=" * 70)

    # 1. Health check & LAN IP resolution (Safeguard #3)
    print("\n[Step 1] Checking /api/health and LAN IP resolution...")
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(f"{server_url}/api/health")
            assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
            health_data = resp.json()
            print(f"  ✓ Health status: {health_data['status']}")
            print(f"  ✓ Resolved Physical LAN IP (Safeguard #3): {health_data['lan_ip']}")
            assert health_data['lan_ip'] != "localhost", "LAN IP resolved to localhost"
        except Exception as e:
            print(f"  ✗ Failed to connect to server: {e}")
            sys.exit(1)

    # 2. Pre-flight Disk Space Check (Safeguard #10)
    print("\n[Step 2] Testing Pre-flight Disk Space Check (Safeguard #10)...")
    file_size_35mb = 35 * 1024 * 1024
    ok, free_bytes, required_bytes = check_disk_space(DOWNLOAD_DIR, file_size_35mb)
    print(f"  ✓ Target Directory: {DOWNLOAD_DIR}")
    print(f"  ✓ Free Space: {free_bytes / (1024**3):.2f} GB | Required: {required_bytes / (1024**2):.2f} MB")
    assert ok, f"Pre-flight disk space failed: free={free_bytes}, required={required_bytes}"

    # 3. Test-File Endpoint Probe (Safeguard #5)
    print("\n[Step 3] Probing /api/test-file/35 (HEAD & Range: bytes=0-0)...")
    async with httpx.AsyncClient(timeout=10.0) as client:
        head_resp = await client.head(f"{server_url}/api/test-file/35")
        assert head_resp.status_code == 200, f"HEAD failed with {head_resp.status_code}"
        assert head_resp.headers.get("accept-ranges") == "bytes", "Missing Accept-Ranges header"
        assert int(head_resp.headers["content-length"]) == file_size_35mb, "Content-Length mismatch"
        etag = head_resp.headers.get("etag")
        print(f"  ✓ HEAD Probe Succeeded: Content-Length={head_resp.headers['content-length']}, ETag={etag}")

        range_resp = await client.get(f"{server_url}/api/test-file/35", headers={"Range": "bytes=0-0"})
        assert range_resp.status_code == 206, f"Range 0-0 failed with {range_resp.status_code}"
        assert len(range_resp.content) == 1, "Range 0-0 content length mismatch"
        print(f"  ✓ Range Probe (bytes=0-0) Succeeded: Content-Range={range_resp.headers.get('content-range')}")

    # 4. Execute 35 MB Download with Single-Writer Instrumentation
    print("\n[Step 4] Executing 35 MB Download with Single-Writer Instrumentation...")
    monitor = FileWriterMonitor()
    monitor.start()

    download_filename = f"verify_stage1_35mb_{int(time.time())}.bin"
    task = SoloDownloadTask(
        job_id="verify-job-1",
        url=f"{server_url}/api/test-file/35",
        filename=download_filename,
        download_dir=DOWNLOAD_DIR,
    )

    try:
        # Start download
        await task.start()
        
        # Observe chunk states during download
        observed_statuses = set()
        while task.status in ("probing", "downloading"):
            for c in task.chunks:
                observed_statuses.add(c.status)
            await asyncio.sleep(0.02)

        # Wait for task completion
        await task._task_handle
        monitor.stop()

        for c in task.chunks:
            observed_statuses.add(c.status)

        assert task.status == "completed", f"Task failed with error: {task.error}"
        print(f"  ✓ Download completed in {task.end_time - task.start_time:.3f}s")
        print(f"  ✓ Observed chunk status transitions: {observed_statuses}")
        assert "queued" in observed_statuses or "downloading" in observed_statuses, "Did not observe queued/downloading states"
        assert all(c.status == "done" for c in task.chunks), "Not all chunks marked done"

    finally:
        monitor.stop()

    # 5. Verify 10 MB Chunk Slicing (Exactly 4 Chunks: 10 + 10 + 10 + 5 MB)
    print("\n[Step 5] Verifying 10 MB Dynamic Micro-Chunk Slicing (Safeguard #1)...")
    print(f"  Total Chunks Generated: {len(task.chunks)}")
    assert len(task.chunks) == 4, f"Expected exactly 4 chunks, got {len(task.chunks)}"

    expected_sizes = [
        CHUNK_SIZE,                     # Chunk 0: 10,485,760 bytes (10 MB)
        CHUNK_SIZE,                     # Chunk 1: 10,485,760 bytes (10 MB)
        CHUNK_SIZE,                     # Chunk 2: 10,485,760 bytes (10 MB)
        file_size_35mb - 3 * CHUNK_SIZE # Chunk 3: 5,242,880 bytes (5 MB)
    ]

    for idx, chunk in enumerate(task.chunks):
        actual_len = chunk.expected_length
        exp_len = expected_sizes[idx]
        print(f"  Chunk #{chunk.chunk_id}: bytes {chunk.start_byte:>8}..{chunk.end_byte:>8} ({actual_len:>8} bytes, {actual_len / (1024*1024):.2f} MB) -> Status: {chunk.status}")
        assert actual_len == exp_len, f"Chunk {idx} size {actual_len} != expected {exp_len}"
        assert chunk.status == "done", f"Chunk {idx} not marked done"

    # 6. Verify SHA-256 Integrity (Resolved locally without relying on items[].path)
    print("\n[Step 6] Verifying SHA-256 Checksum Integrity...")
    served_bytes = get_deterministic_data(35)
    expected_sha256 = hashlib.sha256(served_bytes).hexdigest()
    
    # In Stage 2, completed download is moved to LANPool_Cache/<sha>_<name>
    downloaded_path = DOWNLOAD_DIR / download_filename
    if not downloaded_path.exists():
        cached_target = CACHE_DIR / f"{expected_sha256}_{download_filename}"
        if cached_target.exists():
            downloaded_path = cached_target
        else:
            matches = list(CACHE_DIR.glob(f"*_{download_filename}"))
            if matches:
                downloaded_path = matches[0]

    assert downloaded_path.exists(), f"Could not find downloaded file in {DOWNLOAD_DIR} or {CACHE_DIR}"
    actual_sha256 = compute_file_sha256(downloaded_path)

    print(f"  Artifact Path Resolved:   {downloaded_path}")
    print(f"  Served Bytes SHA-256:     {expected_sha256}")
    print(f"  Downloaded File SHA-256: {actual_sha256}")
    assert actual_sha256 == expected_sha256, "SHA-256 checksum mismatch!"
    print("  ✓ SHA-256 Checksum MATCHES EXACTLY!")

    # 7. Single-Writer Architecture Proof (Safeguard #2 - WinError 32 Guard)
    print("\n[Step 7] Proving Single Dedicated Disk-Writer Architecture (Safeguard #2)...")
    matching_part_keys = [k for k in monitor.writers_by_file if download_filename in k and k.endswith(".part")]
    assert len(matching_part_keys) > 0, "No file open events recorded for .part file"
    
    writers = monitor.writers_by_file[matching_part_keys[0]]
    print(f"  File: {matching_part_keys[0]}")
    print(f"  Asyncio tasks that opened/accessed .part file: {writers}")
    print(f"  Total distinct open calls recorded: {len(monitor.write_events)}")
    
    # Assert only ONE distinct task touched the .part file
    assert len(writers) == 1, f"Multiple tasks accessed the .part file! Writers: {writers}"
    print("  ✓ ARCHITECTURAL INVARIANT PROVEN: Only the dedicated disk-writer task touched the .part file!")

    # 8. Safeguard #4: Poison Assertion Test
    print("\n[Step 8] Testing Safeguard #4 (Captive Portal / HTTP 200 Poison Guard)...")
    # Simulate a network worker encountering HTTP 200 on a Range request
    class MockClient:
        async def get(self, *args, **kwargs):
            # Return HTTP 200 (Captive Portal Login HTML) instead of HTTP 206
            return httpx.Response(
                status_code=200,
                content=b"<html><body>Captive Portal Login Required</body></html>",
                request=httpx.Request("GET", "http://test")
            )

    test_chunk = task.chunks[0]
    test_chunk.status = "queued"
    test_queue = asyncio.Queue()
    await test_queue.put(test_chunk)
    
    test_task = SoloDownloadTask(
        job_id="test-poison",
        url="http://test",
        download_dir=DOWNLOAD_DIR
    )
    test_task.final_url = "http://test"
    test_task.chunks = [test_chunk]
    test_task.chunk_queue = test_queue
    
    worker_task = asyncio.create_task(test_task._network_worker("worker-poison-test", MockClient()))
    await asyncio.sleep(0.1)
    worker_task.cancel()
    
    print(f"  ✓ Poisoned Chunk State after HTTP 200 response: status={test_chunk.status}, retries={test_chunk.retries}")
    assert test_chunk.retries >= 1, "Poisoned chunk retry counter did not increment"
    assert test_task.writer_queue.empty(), "Poisoned chunk bytes leaked to disk writer queue!"
    print("  ✓ Safeguard #4 PROVEN: Non-206 responses are discarded and never sent to disk writer!")

    # Clean up downloaded file
    if downloaded_path.exists():
        downloaded_path.unlink()
        print(f"\nCleaned up verification artifact: {downloaded_path.name}")

    print("\n" + "=" * 70)
    print("ALL VERIFICATION GATES PASSED (100% COMPLIANT WITH STAGE 1 SSOT)")
    print("=" * 70)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    asyncio.run(run_verification(f"http://127.0.0.1:{port}"))
