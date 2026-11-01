#!/usr/bin/env python3
"""
LANPool Stage 2 Verification Gate Script (Including Task 4b Fixes F1-F4 & Tests T1-T5)

Tests:
1. Fresh download via API -> registers in LANPool_Cache/, appears in /api/cache/list (without 'path' field, F4),
   downloads/ copy moved.
2. Lookup exact composite match: url+etag -> hit:true; changed etag -> hit:false; changed url -> hit:false.
3. Stream valid sha256 -> streamed bytes sha256 matches downloaded sha256.
4. Security attack tests (Safeguard #7):
   - ..%2Fmain.py
   - ../../main.py
   - %2e%2e%2fmain.py
   - 63-char hex
   - 65-char hex
   - 64 non-hex chars
   - unknown valid 64-hex sha256
   Each MUST return 400, 403, or 404 with no file content.
5. T1 (F1-a): Temp dir: register same content under two names -> exactly 1 physical file remains (the new one),
   entry points to it, total_bytes == its size.
6. T2 (F1-b): Temp dir: two same-content files pre-placed (no index) -> cold CacheManager -> exactly 1 file
   stays on disk and is indexed.
7. LRU Eviction & Quota Guard (Safeguard #8):
   CacheManager with tiny quota -> 3 files registered -> oldest by mtime evicted, total <= quota.
   Oversized file (> quota) skipped without wiping existing cache.
8. T3 (F3): POST /api/download/start with traversal filenames ("../escaped.bin", "../../board.md", "../.agents/board.md")
   -> must return HTTP 400; nothing created outside downloads/.
9. T4 (F2): No registration race: first poll where download reports "completed": /api/cache/list must already
   contain that sha AND its file must exist on disk. Tested across 3 downloads.
10. T5: Real directory duplicate cleanup: cold-boot scan cleans pre-existing orphan duplicates in LANPool_Cache,
   leaving exactly 1 physical file per hash, du(LANPool_Cache) ~= index total + index file size.
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-test-group-key-not-for-deployment")

import httpx

import core.cache_manager
from config import CACHE_DIR, DOWNLOAD_DIR
from core.cache_manager import CacheManager, compute_file_sha256


async def run_stage2_verification(server_url: str = "http://127.0.0.1:8000"):
    print("=" * 70)
    print("LANPool STAGE 2 VERIFICATION GATE (WITH TASK 4b FIXES & TESTS T1-T5)")
    print(f"Target Server: {server_url}")
    print("=" * 70)

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Step 0: Ensure server is running and healthy
        resp = await client.get(f"{server_url}/api/health")
        assert resp.status_code == 200, f"Server health check failed: {resp.status_code}"
        print(f"Server online. Health: {resp.json()}")

        # ---------------------------------------------------------------------
        # 1. Download 35 MB and verify Cache Registration (Safeguards #6, #8, F4)
        # ---------------------------------------------------------------------
        print("\n[Step 1] Triggering 35 MB Download via API & Verifying Cache Registration...")
        test_filename = f"stage2_test_{int(time.time())}.bin"
        start_payload = {
            "url": f"{server_url}/api/test-file/35",
            "filename": test_filename,
        }
        start_resp = await client.post(f"{server_url}/api/download/start", json=start_payload)
        assert start_resp.status_code == 200, f"Failed to start download: {start_resp.text}"
        job_id = start_resp.json()["job_id"]
        print(f"  ✓ Download job started: {job_id}")

        # Poll status until completed
        final_status = {}
        for _ in range(300):
            status_resp = await client.get(f"{server_url}/api/download/status", params={"job_id": job_id})
            assert status_resp.status_code == 200
            final_status = status_resp.json()
            if final_status["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.05)

        assert final_status["status"] == "completed", f"Download failed: {final_status.get('error')}"
        downloaded_sha256 = final_status["sha256"]
        total_size = final_status["total_size"]
        etag = final_status["etag"]
        print(f"  ✓ Download completed. SHA-256: {downloaded_sha256}, Size: {total_size}, ETag: {etag}")

        # Check /api/cache/list and verify F4 (path dropped)
        list_resp = await client.get(f"{server_url}/api/cache/list")
        assert list_resp.status_code == 200, f"Failed to list cache: {list_resp.text}"
        cache_data = list_resp.json()
        matching_items = [it for it in cache_data["items"] if it["sha256"] == downloaded_sha256]
        assert len(matching_items) == 1, f"Downloaded item not found in cache list: {cache_data}"
        cached_item = matching_items[0]
        
        # F4 Assertion: verify 'path' is NOT exposed in the API item response
        assert "path" not in cached_item, f"F4 Violation! Absolute path leaked in /api/cache/list: {cached_item}"
        print("  ✓ F4 Verified: 'path' is NOT exposed in /api/cache/list items.")
        print(f"  ✓ Cache metadata returned: filename={cached_item['filename']}, size={cached_item['size']}")

        # Resolve physical file locally in CACHE_DIR without relying on API path
        local_matches = list(CACHE_DIR.glob(f"{downloaded_sha256}_{test_filename}"))
        assert len(local_matches) == 1, f"Expected exactly 1 cached file matching {downloaded_sha256}_{test_filename}"
        cached_file_path = local_matches[0]
        assert cached_file_path.exists(), f"Cached file not found on disk: {cached_file_path}"
        download_copy_path = DOWNLOAD_DIR / test_filename
        assert not download_copy_path.exists(), f"File was not moved! Still exists in downloads/: {download_copy_path}"
        print(f"  ✓ Physical file verified in LANPool_Cache/: {cached_file_path.name}")
        print(f"  ✓ Verified file moved: {download_copy_path.name} is no longer in downloads/")

        # ---------------------------------------------------------------------
        # 2. Cache Lookup with Composite Key (Safeguard #6)
        # ---------------------------------------------------------------------
        print("\n[Step 2] Testing Stale Cache Prevention via ETag Composite Lookup (Safeguard #6)...")
        # Exact match
        lookup_hit = await client.get(
            f"{server_url}/api/cache/lookup",
            params={"url": f"{server_url}/api/test-file/35", "etag": etag}
        )
        assert lookup_hit.status_code == 200
        hit_json = lookup_hit.json()
        print(f"  ✓ Matching (url + etag): {hit_json}")
        assert hit_json.get("hit") is True, f"Expected cache hit, got {hit_json}"
        assert hit_json.get("sha256") == downloaded_sha256
        assert hit_json.get("size") == total_size

        # Changed ETag -> hit: false
        lookup_etag_miss = await client.get(
            f"{server_url}/api/cache/lookup",
            params={"url": f"{server_url}/api/test-file/35", "etag": "stale-etag-9999"}
        )
        assert lookup_etag_miss.status_code == 200
        print(f"  ✓ Changed ETag (stale): {lookup_etag_miss.json()}")
        assert lookup_etag_miss.json().get("hit") is False, "Expected miss on changed ETag!"

        # Changed URL -> hit: false
        lookup_url_miss = await client.get(
            f"{server_url}/api/cache/lookup",
            params={"url": "http://other-cdn.com/file", "etag": etag}
        )
        assert lookup_url_miss.status_code == 200
        print(f"  ✓ Changed URL: {lookup_url_miss.json()}")
        assert lookup_url_miss.json().get("hit") is False, "Expected miss on changed URL!"

        # ---------------------------------------------------------------------
        # 3. Stream Valid SHA-256 (Safeguard #7)
        # ---------------------------------------------------------------------
        print("\n[Step 3] Streaming Valid SHA-256 via /api/cache/stream/{sha256}...")
        stream_resp = await client.get(f"{server_url}/api/cache/stream/{downloaded_sha256}")
        assert stream_resp.status_code == 200, f"Stream failed: {stream_resp.status_code}"
        streamed_sha256 = hashlib.sha256(stream_resp.content).hexdigest()
        assert streamed_sha256 == downloaded_sha256, f"Streamed bytes sha {streamed_sha256} != expected {downloaded_sha256}"
        print(f"  ✓ Streamed {len(stream_resp.content)} bytes at full speed.")
        print(f"  ✓ Streamed SHA-256: {streamed_sha256} MATCHES EXACTLY!")

        # ---------------------------------------------------------------------
        # 4. Security Attack Tests: Path Traversal & Invalid Hashes (Safeguard #7)
        # ---------------------------------------------------------------------
        print("\n[Step 4] Executing Path Traversal & Malicious Request Security Suite (Safeguard #7)...")
        attack_vectors = [
            ("..%2Fmain.py", "URL-encoded relative traversal ..%2F"),
            ("../../main.py", "Literal path traversal ../../"),
            ("%2e%2e%2fmain.py", "Double-encoded path traversal %2e%2e%2f"),
            ("a" * 63, "Short hex length (63 chars)"),
            ("a" * 65, "Long hex length (65 chars)"),
            ("g" * 64, "Non-hex characters ('g' * 64)"),
            ("z" * 64, "Non-hex characters ('z' * 64)"),
            ("0123456789abcdef" * 4, "Valid 64-hex but unknown hash"),
        ]

        for vector, description in attack_vectors:
            attack_url = f"{server_url}/api/cache/stream/{vector}"
            res = await client.get(attack_url)
            print(f"  Vector [{description}]: HTTP {res.status_code}")
            assert res.status_code in (400, 403, 404), f"Security breach! Vector '{vector}' returned {res.status_code}"
            assert b"FastAPI" not in res.content and b"def " not in res.content, f"Content leaked for vector {vector}!"
        print("  ✓ ALL PATH TRAVERSAL AND HASH VALIDATION ATTACKS SAFELY BLOCKED!")

        # ---------------------------------------------------------------------
        # 5. T3 (F3): Path Traversal Filename Rejection in POST /api/download/start
        # ---------------------------------------------------------------------
        print("\n[Step 5 / T3] Testing F3 Trust Boundary on POST /api/download/start Filename...")
        traversal_filenames = [
            "../escaped.bin",
            "../../board.md",
            "../.agents/board.md",
            "sub/dir/nested.bin",
            "..\\windows_traversal.bin",
            "..",
            ".",
            "",
            "   ",
            "a\x00b",
        ]

        for tf in traversal_filenames:
            bad_resp = await client.post(
                f"{server_url}/api/download/start",
                json={"url": f"{server_url}/api/test-file/35", "filename": tf}
            )
            print(f"  Filename {tf!r}: HTTP {bad_resp.status_code}")
            assert bad_resp.status_code == 400, f"Expected HTTP 400 for filename '{tf}', got {bad_resp.status_code}"

        # Assert nothing was created outside downloads/
        escaped_check = Path("escaped.bin")
        assert not escaped_check.exists(), "T3 Failed: escaped.bin was created in project root!"

        # Benign double dots must be ALLOWED: foo..bar.bin -> 200
        benign_resp = await client.post(
            f"{server_url}/api/download/start",
            json={"url": f"{server_url}/api/test-file/1", "filename": "foo..bar.bin"}
        )
        print(f"  Filename 'foo..bar.bin': HTTP {benign_resp.status_code}")
        assert benign_resp.status_code == 200, f"Expected HTTP 200 for benign 'foo..bar.bin', got {benign_resp.status_code}"
        b_jid = benign_resp.json()["job_id"]
        while True:
            b_st = (await client.get(f"{server_url}/api/download/status", params={"job_id": b_jid})).json()
            if b_st["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.02)
        # Clean up downloaded benign test file from cache and downloads
        for f in CACHE_DIR.glob("*_foo..bar.bin"):
            f.unlink(missing_ok=True)
        (DOWNLOAD_DIR / "foo..bar.bin").unlink(missing_ok=True)
        print("  ✓ T3 Passed: All traversal filenames rejected with HTTP 400; benign double dots accepted (200); zero files escaped.")

        # ---------------------------------------------------------------------
        # 6. T4 (F2): Registration Race Elimination
        # ---------------------------------------------------------------------
        print("\n[Step 6 / T4] Testing F2 Registration Race Elimination (3 repetitions)...")
        for iteration in range(3):
            race_filename = f"race_test_iter_{iteration}_{int(time.time())}.bin"
            resp_start = await client.post(
                f"{server_url}/api/download/start",
                json={"url": f"{server_url}/api/test-file/35", "filename": race_filename}
            )
            assert resp_start.status_code == 200
            j_id = resp_start.json()["job_id"]

            # Poll until the very first time status == 'completed'
            first_completed_time = None
            while True:
                poll_resp = await client.get(f"{server_url}/api/download/status", params={"job_id": j_id})
                data = poll_resp.json()
                if data["status"] == "completed":
                    first_completed_time = time.time()
                    break
                await asyncio.sleep(0.01)

            # Instantly verify /api/cache/list contains that sha
            c_list = (await client.get(f"{server_url}/api/cache/list")).json()
            cached_shas = {it["sha256"] for it in c_list["items"]}
            assert downloaded_sha256 in cached_shas, f"T4 Race Condition! Job completed but sha not in cache index!"
            
            # Instantly verify physical file exists
            matching_files = list(CACHE_DIR.glob(f"{downloaded_sha256}_{race_filename}"))
            assert len(matching_files) == 1 and matching_files[0].exists(), "T4 Race Condition! File not on disk!"
            print(f"  ✓ Repetition {iteration + 1}: On first 'completed' poll, file already indexed and on disk.")

        print("  ✓ T4 Passed: Zero race conditions between download completion and cache registration.")

    # -------------------------------------------------------------------------
    # 7. T1 (F1-a) & T2 (F1-b) & LRU Eviction Unit Tests
    # -------------------------------------------------------------------------
    print("\n[Step 7 / T1, T2] Testing T1 Duplicate Overwrite & T2 Cold-Boot Dedup in Temp Dir...")
    temp_cache_dir = Path(tempfile.mkdtemp(prefix="lanpool_cache_unit_test_"))
    try:
        # T1: Register same content under two different names -> exactly 1 physical file remains (the new one)
        cm_t1 = CacheManager(cache_dir=temp_cache_dir, max_cache_bytes=50000)
        content_a = b"DUPLICATE_CONTENT_PAYLOAD_BYTES" * 100
        sha_a = hashlib.sha256(content_a).hexdigest()

        src_a1 = temp_cache_dir / "src_a1.bin"
        src_a2 = temp_cache_dir / "src_a2.bin"
        src_a1.write_bytes(content_a)
        src_a2.write_bytes(content_a)

        assert cm_t1.register_completed(src_a1, "http://test/a1", "etag_a", sha_a, "name_one.bin", len(content_a))
        file_one_matches = list(temp_cache_dir.glob(f"{sha_a}_name_one.bin"))
        assert len(file_one_matches) == 1, "First file not in cache"

        # Register second file with same sha but new name
        time.sleep(0.05)
        assert cm_t1.register_completed(src_a2, "http://test/a2", "etag_a", sha_a, "name_two.bin", len(content_a))
        
        # Verify F1(a): exactly ONE physical file remains for sha_a (name_two.bin)
        all_sha_files = [f for f in temp_cache_dir.glob(f"{sha_a}_*") if f.is_file()]
        print(f"  Physical files for sha_a: {[f.name for f in all_sha_files]}")
        assert len(all_sha_files) == 1, f"T1 Failed: Expected 1 file, found {len(all_sha_files)}: {all_sha_files}"
        assert all_sha_files[0].name == f"{sha_a}_name_two.bin", "T1 Failed: New file name was not preserved!"
        assert cm_t1.get_total_bytes() == len(content_a), f"T1 Failed: total_bytes {cm_t1.get_total_bytes()} != {len(content_a)}"
        print("  ✓ T1 Passed: Registering same content under a new name unlinks the superseded physical file.")

        # T2: Two same-content files pre-placed on disk without index -> cold CacheManager -> exactly 1 file kept
        temp_dir_t2 = Path(tempfile.mkdtemp(prefix="lanpool_cache_t2_"))
        try:
            p_dup1 = temp_dir_t2 / f"{sha_a}_copy1.bin"
            p_dup2 = temp_dir_t2 / f"{sha_a}_copy2.bin"
            p_dup1.write_bytes(content_a)
            time.sleep(0.05)
            p_dup2.write_bytes(content_a)

            # Cold boot on temp_dir_t2
            cm_t2 = CacheManager(cache_dir=temp_dir_t2, max_cache_bytes=50000)
            t2_files = [f for f in temp_dir_t2.glob(f"{sha_a}_*") if f.is_file()]
            print(f"  Physical files after T2 cold boot scan: {[f.name for f in t2_files]}")
            assert len(t2_files) == 1, f"T2 Failed: Expected 1 file after scan deduplication, found {len(t2_files)}"
            assert cm_t2.get_total_bytes() == len(content_a), "T2 Failed: Index total bytes mismatch!"
            print("  ✓ T2 Passed: Cold-boot scan deduplicated same-sha files on disk, leaving exactly 1 file.")
        finally:
            shutil.rmtree(temp_dir_t2, ignore_errors=True)

        # LRU Eviction & Oversized File Test (Safeguard #8)
        quota_bytes = 2500
        cm_lru = CacheManager(cache_dir=temp_cache_dir, max_cache_bytes=quota_bytes)
        f1_data, f2_data, f3_data = b"X" * 1000, b"Y" * 1000, b"Z" * 1000
        p1, p2, p3 = temp_cache_dir / "f1.bin", temp_cache_dir / "f2.bin", temp_cache_dir / "f3.bin"
        p1.write_bytes(f1_data); p2.write_bytes(f2_data); p3.write_bytes(f3_data)
        s1 = hashlib.sha256(f1_data).hexdigest()
        s2 = hashlib.sha256(f2_data).hexdigest()
        s3 = hashlib.sha256(f3_data).hexdigest()

        cm_lru.register_completed(p1, "http://t/1", "e1", s1, "f1.bin", 1000)
        time.sleep(0.05)
        cm_lru.register_completed(p2, "http://t/2", "e2", s2, "f2.bin", 1000)
        time.sleep(0.05)
        cm_lru.register_completed(p3, "http://t/3", "e3", s3, "f3.bin", 1000)

        assert s1 not in cm_lru.approved_hash_map, "Oldest entry was not evicted!"
        assert s2 in cm_lru.approved_hash_map and s3 in cm_lru.approved_hash_map
        assert cm_lru.get_total_bytes() <= quota_bytes
        print("  ✓ LRU Eviction verified: Oldest entry by mtime pruned when exceeding quota.")

        # Oversized file guard
        p_big = temp_cache_dir / "big.bin"
        p_big.write_bytes(b"B" * 3000)
        s_big = hashlib.sha256(p_big.read_bytes()).hexdigest()
        assert cm_lru.register_completed(p_big, "http://t/b", "eb", s_big, "big.bin", 3000) is False
        assert s2 in cm_lru.approved_hash_map and s3 in cm_lru.approved_hash_map, "Cache wiped by oversized file!"
        print("  ✓ Oversized file skipped without wiping cache.")

    finally:
        shutil.rmtree(temp_cache_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 8. T5 (Real Directory): Cold-Boot Cleans Orphan Duplicates in LANPool_Cache
    # -------------------------------------------------------------------------
    print("\n[Step 8 / T5] Testing Real LANPool_Cache Cold-Boot Duplicate Cleanup...")
    # Boot a new CacheManager pointing directly at real CACHE_DIR
    cm_real = CacheManager(cache_dir=CACHE_DIR)
    
    # Check that for each unique sha256 in approved_hash_map, exactly 1 physical file exists on disk
    physical_bin_files = [f for f in CACHE_DIR.iterdir() if f.is_file() and not f.name.startswith(".") and f.name != "cache_index.json" and not f.name.endswith(".tmp")]
    print(f"  Physical files in {CACHE_DIR.name}: {len(physical_bin_files)}")
    print(f"  Index count: {len(cm_real.approved_hash_map)}")
    
    # Assert physical file count matches unique sha count
    assert len(physical_bin_files) == len(cm_real.approved_hash_map), f"T5 Failed: Orphan files remain! Physical={len(physical_bin_files)}, Index={len(cm_real.approved_hash_map)}"
    
    for sha, item in cm_real.approved_hash_map.items():
        matching = list(CACHE_DIR.glob(f"{sha}_*"))
        assert len(matching) == 1, f"T5 Failed: Hash {sha} has {len(matching)} files on disk: {matching}"

    # Verify disk usage du matches index total + index file size (within 4KB block margin)
    total_index_size = cm_real.get_total_bytes()
    actual_disk_size = sum(f.stat().st_size for f in physical_bin_files)
    print(f"  Index total bytes: {total_index_size} | Disk physical bytes: {actual_disk_size}")
    assert actual_disk_size == total_index_size, "T5 Failed: Physical bytes on disk do not match index total!"
    print("  ✓ T5 Passed: Real LANPool_Cache cold-boot scan pruned all orphan duplicates. Disk usage matches index exactly.")

    # -------------------------------------------------------------------------
    # 9. T6: Fast Boot-Scan Path & Dedupe Invariant
    # -------------------------------------------------------------------------
    print("\n[Step 9 / T6] Testing T6 Fast Boot-Scan Path & Dedupe Invariant...")
    temp_dir_t6 = Path(tempfile.mkdtemp(prefix="lanpool_cache_t6_"))
    try:
        content_t6 = b"FAST_BOOT_SCAN_PAYLOAD_BYTES_VERIFICATION" * 100
        sha_t6 = hashlib.sha256(content_t6).hexdigest()
        t6_file = temp_dir_t6 / f"{sha_t6}_testfile.bin"
        t6_file.write_bytes(content_t6)
        stat_t6 = t6_file.stat()

        index_data = {
            sha_t6: {
                "sha256": sha_t6,
                "path": str(t6_file.resolve()),
                "url": "http://test/t6",
                "etag": "etag_t6",
                "filename": "testfile.bin",
                "size": stat_t6.st_size,
                "mtime": stat_t6.st_mtime,
                "mtime_ns": stat_t6.st_mtime_ns,
            }
        }
        (temp_dir_t6 / "cache_index.json").write_text(json.dumps(index_data, indent=2))

        # Monkeypatch compute_file_sha256 to count hashing calls
        orig_compute = core.cache_manager.compute_file_sha256
        call_count = 0

        def counted_compute(p):
            nonlocal call_count
            call_count += 1
            return orig_compute(p)

        core.cache_manager.compute_file_sha256 = counted_compute
        try:
            # Sub-test 1: Indexed, unchanged file -> ZERO calls to compute_file_sha256
            call_count = 0
            cm_t6_1 = CacheManager(cache_dir=temp_dir_t6, max_cache_bytes=50000)
            print(f"  Unchanged file hash calls: {call_count}")
            assert call_count == 0, f"T6 Failed: Expected 0 hash calls for unchanged file, got {call_count}"
            assert sha_t6 in cm_t6_1.approved_hash_map, "T6 Failed: Hash not in approved_hash_map!"
            print("  ✓ T6.1 Passed: Unchanged file used fast path (0 hash calls).")

            # Sub-test 2: Change only mtime -> re-hashed (1 call)
            call_count = 0
            os.utime(t6_file, (stat_t6.st_atime + 10, stat_t6.st_mtime + 10))
            cm_t6_2 = CacheManager(cache_dir=temp_dir_t6, max_cache_bytes=50000)
            print(f"  Mtime-changed file hash calls: {call_count}")
            assert call_count == 1, f"T6 Failed: Expected 1 hash call after mtime change, got {call_count}"
            assert sha_t6 in cm_t6_2.approved_hash_map
            print("  ✓ T6.2 Passed: File with changed mtime was re-hashed (1 hash call).")

            # Sub-test 3: Change size -> re-hashed (1 call)
            call_count = 0
            t6_file.write_bytes(content_t6 + b"_EXTRA_APPENDED_BYTES")
            new_sha = hashlib.sha256(t6_file.read_bytes()).hexdigest()
            cm_t6_3 = CacheManager(cache_dir=temp_dir_t6, max_cache_bytes=50000)
            print(f"  Size-changed file hash calls: {call_count}")
            assert call_count == 1, f"T6 Failed: Expected 1 hash call after size change, got {call_count}"
            assert new_sha in cm_t6_3.approved_hash_map
            print("  ✓ T6.3 Passed: File with changed size was re-hashed (1 hash call).")

            # Reset files in temp_dir_t6 back to original content and rebuild clean index with mtime_ns
            for f in temp_dir_t6.glob("*.bin"):
                f.unlink(missing_ok=True)
            (temp_dir_t6 / "cache_index.json").unlink(missing_ok=True)
            t6_file = temp_dir_t6 / f"{sha_t6}_testfile.bin"
            t6_file.write_bytes(content_t6)
            stat_t6 = t6_file.stat()
            clean_index = {
                sha_t6: {
                    "sha256": sha_t6,
                    "path": str(t6_file.resolve()),
                    "url": "http://test/t6",
                    "etag": "etag_t6",
                    "filename": "testfile.bin",
                    "size": stat_t6.st_size,
                    "mtime": stat_t6.st_mtime,
                    "mtime_ns": stat_t6.st_mtime_ns,
                }
            }
            (temp_dir_t6 / "cache_index.json").write_text(json.dumps(clean_index, indent=2))

            # Sub-test 4: Add an unindexed file -> re-hashed (1 call; unchanged indexed file has 0 calls)
            call_count = 0
            unindexed_file = temp_dir_t6 / "unindexed_brand_new.bin"
            unindexed_file.write_bytes(b"BRAND_NEW_UNINDEXED_PAYLOAD")
            cm_t6_4 = CacheManager(cache_dir=temp_dir_t6, max_cache_bytes=50000)
            print(f"  Indexed + unindexed hash calls: {call_count}")
            assert call_count == 1, f"T6 Failed: Expected 1 hash call for new unindexed file, got {call_count}"
            unindexed_file.unlink(missing_ok=True)
            print("  ✓ T6.4 Passed: Unindexed file re-hashed while indexed file bypassed.")

            # Sub-test 5: Dedupe still removes same-sha duplicate when fast path is in play
            t6_dup = temp_dir_t6 / f"{sha_t6}_dup_copy.bin"
            t6_dup.write_bytes(content_t6)
            cm_t6_5 = CacheManager(cache_dir=temp_dir_t6, max_cache_bytes=50000)
            leftover_files = [f.name for f in temp_dir_t6.glob(f"{sha_t6}_*")]
            print(f"  Files remaining after dedupe under fast-scan: {leftover_files}")
            assert len(leftover_files) == 1, f"T6 Failed: Expected 1 file after dedupe, got {leftover_files}"
            assert leftover_files == [t6_file.name], f"T6 Failed: Expected indexed file preserved, got {leftover_files}"
            print("  ✓ T6.5 Passed: Dedupe unlinked same-sha duplicate even with fast path active.")

        finally:
            core.cache_manager.compute_file_sha256 = orig_compute
    finally:
        shutil.rmtree(temp_dir_t6, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 10. T7: Cache Poisoning Prevention & Naming Invariant (F5 & F6)
    # -------------------------------------------------------------------------
    print("\n[Step 10 / T7] Testing T7 Cache Poisoning Prevention & Naming Invariant...")
    temp_dir_t7 = Path(tempfile.mkdtemp(prefix="lanpool_cache_t7_"))
    try:
        content_A = b"ORIGINAL_PAYLOAD_CONTENT_A" * 50
        content_B = b"MODIFIED_PAYLOAD_CONTENT_B_LONGER" * 50
        sha_A = hashlib.sha256(content_A).hexdigest()
        sha_B = hashlib.sha256(content_B).hexdigest()

        # T7.1 & T7.2: Full poisoning scenario & naming invariant
        # 1. Index sha_A -> file {sha_A}_x.bin
        cm_t7 = CacheManager(cache_dir=temp_dir_t7, max_cache_bytes=100000)
        src_A = temp_dir_t7 / "src_A.bin"
        src_A.write_bytes(content_A)
        assert cm_t7.register_completed(src_A, "http://test/A", "etag_A", sha_A, "x.bin", len(content_A))

        file_A = temp_dir_t7 / f"{sha_A}_x.bin"
        assert file_A.exists(), "Initial file for sha_A not created"

        # 2. Change content of that file in place to content_B
        file_A.write_bytes(content_B)

        # 3. Cold scan: boot a new CacheManager
        cm_t7_cold = CacheManager(cache_dir=temp_dir_t7, max_cache_bytes=100000)

        # T7.2 Check naming invariant:
        # The file on disk must now be renamed to start with actual sha_B
        files_on_disk = [f.name for f in temp_dir_t7.glob("*.bin") if not f.name.startswith(".")]
        print(f"  Files after cold scan: {files_on_disk}")
        assert f"{sha_B}_x.bin" in files_on_disk, f"T7.2 Failed: File was not renamed to {sha_B}_x.bin! Found: {files_on_disk}"
        assert f"{sha_A}_x.bin" not in files_on_disk, f"T7.2 Failed: Old name {sha_A}_x.bin still exists!"
        print("  ✓ T7.2 Passed: Naming invariant restored (file renamed to actual sha prefix).")

        # 4. Now re-download original content A
        src_A2 = temp_dir_t7 / "src_A2.bin"
        src_A2.write_bytes(content_A)
        assert cm_t7_cold.register_completed(src_A2, "http://test/A", "etag_A", sha_A, "x.bin", len(content_A))

        # T7.1 Check:
        # Assert: 2 entries, 2 DISTINCT physical paths, each path's bytes hash to its own sha,
        # and no two entries share a resolved path.
        assert len(cm_t7_cold.approved_hash_map) == 2, f"Expected 2 entries, got {len(cm_t7_cold.approved_hash_map)}"
        assert sha_A in cm_t7_cold.approved_hash_map and sha_B in cm_t7_cold.approved_hash_map

        path_A = Path(cm_t7_cold.approved_hash_map[sha_A]["path"]).resolve()
        path_B = Path(cm_t7_cold.approved_hash_map[sha_B]["path"]).resolve()
        assert path_A != path_B, f"T7.1 Failed: Both shas share path: {path_A}"
        assert path_A.exists() and path_B.exists(), "T7.1 Failed: Files do not exist on disk"
        assert hashlib.sha256(path_A.read_bytes()).hexdigest() == sha_A, "T7.1 Failed: path_A content mismatch"
        assert hashlib.sha256(path_B.read_bytes()).hexdigest() == sha_B, "T7.1 Failed: path_B content mismatch"
        print("  ✓ T7.1 Passed: 2 entries, 2 distinct physical paths, byte hashes match, zero path collisions.")

        # T7.3 Collision guard:
        # Pre-create an orphan at destination with junk (not indexed),
        # then register content under that filename -> junk unlinked, file holds correct bytes, index consistent
        orphan_dest = temp_dir_t7 / f"{sha_A}_orphan.bin"
        orphan_dest.write_bytes(b"STALE_UNINDEXED_ORPHAN_JUNK_PAYLOAD_BYTES")
        assert orphan_dest.name not in [Path(it["path"]).name for it in cm_t7_cold.approved_hash_map.values()]

        src_A3 = temp_dir_t7 / "src_A3.bin"
        src_A3.write_bytes(content_A)
        assert cm_t7_cold.register_completed(src_A3, "http://test/A3", "etag_A3", sha_A, "orphan.bin", len(content_A))

        assert orphan_dest.exists(), "Collision destination file does not exist"
        assert orphan_dest.read_bytes() == content_A, "T7.3 Failed: Destination file still contains junk!"
        matching_entries = [s for s, it in cm_t7_cold.approved_hash_map.items() if Path(it["path"]).resolve() == orphan_dest.resolve()]
        assert len(matching_entries) == 1 and matching_entries[0] == sha_A, f"T7.3 Failed: Expected 1 entry, got {matching_entries}"
        print("  ✓ T7.3 Passed: Orphan collision unlinked before move, file holds correct bytes, index consistent.")

    finally:
        shutil.rmtree(temp_dir_t7, ignore_errors=True)

    print("\n" + "=" * 70)
    print("ALL STAGE 2 & TASK 4b / TASK 5b FIX VERIFICATION GATES PASSED (100% COMPLIANT)")
    print("=" * 70)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    asyncio.run(run_stage2_verification(f"http://127.0.0.1:{port}"))
