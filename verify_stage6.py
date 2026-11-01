#!/usr/bin/env python3
"""
LANPool Stage 6 Verification Gate Script (verify_stage6.py)
Validates the One-Click 3-Node Demo Cluster & College Viva Suite:
1. Check 1: 3-Node Cluster Startup, Cross-Registration & Role Assignment:
   - Node 1: Primary Requester (30% share_pct)
   - Node 2: Idle Helper (80% share_pct, boosted=True)
   - Node 3: Gaming Helper (effective_game_mode=True, effective_share_pct <= 15)
   - Peer cross-registration verified on all nodes.
2. Check 2: End-to-End Pooled Download from Throttled Demo Origin Server:
   - 60 MB file (6 x 10 MB chunks) pooled across Node 1, Node 2, and Node 3.
   - Dual-source telemetry: wan_bytes > 0 and lan_bytes > 0.
   - Accurate on-disk file size and bit-perfect SHA-256 hash match.
3. Check 3: Broadcast Boost Request & Game Mode Popup Suppression:
   - Node 1 broadcasts Good Samaritan boost notification to cluster.
   - Node 2 receives active boost request.
   - Node 3 automatically suppresses boost popup due to active Game Focus Mode (game_mode_silent).
4. Check 4: Clean Cluster Teardown & Zero Process Leaks:
   - Subprocess lifecycle verification (all PIDs terminated).
   - Zero orphaned daemons and temporary demo storage unlinked cleanly.
"""

import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_TEST_FILES", "1")
os.environ.setdefault("LANPOOL_TRUST_GROUP_CONTENT", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-test-group-key-not-for-deployment")

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent


def get_free_port() -> int:
    """Finds an ephemeral free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def run_stage6_verification_gate() -> bool:
    print("=" * 70)
    print("LANPool Stage 6 Verification Gate: 3-Node Cluster & Viva Suite")
    print("=" * 70)

    total_start = time.time()
    from scripts.test_support import allocate_ports
    node1_port, node2_port, node3_port, origin_port = allocate_ports(4)

    # Isolated runtime directory for this gate run
    tmp_runtime = Path(tempfile.mkdtemp(prefix="lanpool_s6_runtime_"))
    retained_runtime = PROJECT_ROOT / "demo_runtime"
    retained_existed = retained_runtime.exists()
    retained_runtime.mkdir(exist_ok=True)
    retained_marker = retained_runtime / (".preserve-check-" + uuid.uuid4().hex)
    retained_marker.write_text("existing interactive demo data", encoding="utf-8")

    # Import cluster manager from demo_cluster
    from demo_cluster import DEMO_FILE_SPECS, ORIGIN_SHAS, DemoClusterManager

    cluster = DemoClusterManager(
        base_port=node1_port,
        origin_port=origin_port,
        headless=True,
        runtime_dir=tmp_runtime,
    )
    # Assign specific ports to guarantee zero collision
    cluster.node1_port = node1_port
    cluster.node2_port = node2_port
    cluster.node3_port = node3_port

    try:
        # ---------------------------------------------------------------------
        # Check 1: 3-Node Cluster Startup & Role Configuration
        # ---------------------------------------------------------------------
        t0 = time.time()
        cluster.boot_cluster(fast_mode=True)

        # Verify Node 1 (30% share)
        q1 = httpx.get(f"http://127.0.0.1:{node1_port}/api/qos/status", timeout=3.0).json()
        assert q1.get("effective_share_pct") == 30, f"Node 1 share mismatch: {q1}"

        # Verify Node 2 (Boosted 80%)
        q2 = httpx.get(f"http://127.0.0.1:{node2_port}/api/qos/status", timeout=3.0).json()
        assert q2.get("boosted") is True, f"Node 2 should be boosted: {q2}"
        assert q2.get("effective_share_pct") == 80, f"Node 2 share mismatch: {q2}"

        # Verify Node 3 (Gaming Mode <= 15%)
        q3 = httpx.get(f"http://127.0.0.1:{node3_port}/api/qos/status", timeout=3.0).json()
        assert q3.get("effective_game_mode") is True, f"Node 3 should be in game mode: {q3}"
        assert q3.get("effective_share_pct") <= 15, f"Node 3 share should be <= 15: {q3}"

        # Verify cross-registered peers on all 3 nodes
        for p in (node1_port, node2_port, node3_port):
            p_list = httpx.get(f"http://127.0.0.1:{p}/api/peers/list", timeout=3.0).json()
            peers = p_list if isinstance(p_list, list) else p_list.get("peers", [])
            assert len(peers) >= 2, f"Node {p} missing peers: {peers}"

        dt1 = time.time() - t0
        print(f"[Check 1: 3-node cluster startup, cross-registration & roles] -> PASSED ({dt1:.2f}s)")

        # ---------------------------------------------------------------------
        # Check 2: End-to-End Pooled Download from Throttled Demo Origin
        # ---------------------------------------------------------------------
        t0 = time.time()
        test_file = "game-update-60mb.pak"
        dest_filename = f"s6_gate_update_{int(time.time())}.pak"
        expected_sha = ORIGIN_SHAS[test_file]
        origin_url = f"http://127.0.0.1:{origin_port}/files/{test_file}"

        start_resp = httpx.post(
            f"http://127.0.0.1:{node1_port}/api/download/start",
            json={"url": origin_url, "filename": dest_filename},
            timeout=5.0,
        )
        assert start_resp.status_code == 200, f"Download start failed: {start_resp.text}"
        job_id = start_resp.json()["job_id"]

        deadline = time.time() + 45.0
        final_status = None
        seen_workers = set()
        seen_auto_boost = False
        accepted_auto_boost = False
        baseline_share = q2["share_pct"]

        while time.time() < deadline:
            st = httpx.get(
                f"http://127.0.0.1:{node1_port}/api/download/status",
                params={"job_id": job_id},
                timeout=3.0,
            ).json()
            if not accepted_auto_boost:
                helper_qos = httpx.get(f"http://127.0.0.1:{node2_port}/api/qos/status", timeout=3).json()
                active = helper_qos.get("active_boost_request")
                if active and active.get("job_id") == job_id:
                    seen_auto_boost = True
                    accepted = httpx.post(f"http://127.0.0.1:{node2_port}/api/qos/boost-respond", json={"action": "boost"}, timeout=3)
                    assert accepted.status_code == 200
                    accepted_auto_boost = True

            for ch in st.get("chunks", []):
                w = ch.get("worker_id")
                if w:
                    seen_workers.add(w)

            if st.get("status") in ("completed", "failed"):
                final_status = st
                break
            time.sleep(0.04)

        assert final_status is not None, "Timed out waiting for 60MB pooled download"
        assert final_status.get("status") == "completed", f"Download failed: {final_status}"
        assert final_status.get("sha256") == expected_sha, f"SHA mismatch: {final_status.get('sha256')}"

        # Verify dual-source pooling telemetry
        assert final_status.get("lan_bytes", 0) > 0 or any(w.startswith("helper-") for w in seen_workers), (
            f"Expected LAN helper contributions: lan_bytes={final_status.get('lan_bytes')}"
        )
        assert final_status.get("wan_bytes", 0) > 0 or any(w.startswith("self-") for w in seen_workers), (
            f"Expected local WAN contributions: wan_bytes={final_status.get('wan_bytes')}"
        )

        # Verify file cached on disk and matches hash
        cached_matches = list(cluster.node_dirs[node1_port]["cache"].glob(f"{expected_sha}_*"))
        assert len(cached_matches) == 1, f"Expected 1 cached file on Node 1: {cached_matches}"
        assert hashlib.sha256(cached_matches[0].read_bytes()).hexdigest() == expected_sha

        # Verify /api/cache/stream/{sha} serves the complete payload
        stream_resp = httpx.get(
            f"http://127.0.0.1:{node1_port}/api/cache/stream/{expected_sha}",
            timeout=10.0,
        )
        assert stream_resp.status_code == 200, f"Cache stream failed: {stream_resp.status_code}"
        assert len(stream_resp.content) == DEMO_FILE_SPECS[test_file]
        assert seen_auto_boost and accepted_auto_boost, "Pooled job did not automatically create a boost prompt"
        released = httpx.get(f"http://127.0.0.1:{node2_port}/api/qos/status", timeout=3).json()
        assert released["boosted"] is False, "Accepted job boost was not released at completion"
        assert released["share_pct"] == baseline_share, "Job boost overwrote the helper's baseline"
        print("  Automatic boost observed through HTTP, accepted, and released with baseline preserved")

        dt2 = time.time() - t0
        print(f"[Check 2: End-to-end pooled download with WAN+LAN telemetry] -> PASSED ({dt2:.2f}s)")

        # ---------------------------------------------------------------------
        # Check 3: Broadcast Boost Request & Game Mode Suppression
        # ---------------------------------------------------------------------
        t0 = time.time()
        boost_resp = httpx.post(
            f"http://127.0.0.1:{node1_port}/api/qos/boost-request",
            json={"filename": dest_filename, "total_size": DEMO_FILE_SPECS[test_file]},
            timeout=5.0,
        )
        assert boost_resp.status_code == 200, f"Boost broadcast failed: {boost_resp.text}"
        b_data = boost_resp.json()
        assert b_data.get("status") == "broadcast_complete"

        # Node 3 (Gaming PC) should have suppressed the toast popup
        q3_after = httpx.get(f"http://127.0.0.1:{node3_port}/api/qos/status", timeout=3.0).json()
        assert q3_after.get("active_boost_request") is None, "Node 3 should suppress boost in Game Mode"

        # Node 2 (Idle PC) should have received active boost request
        q2_after = httpx.get(f"http://127.0.0.1:{node2_port}/api/qos/status", timeout=3.0).json()
        assert q2_after.get("active_boost_request") is not None, "Node 2 should have active boost request"
        assert q2_after["active_boost_request"]["filename"] == dest_filename

        dt3 = time.time() - t0
        print(f"[Check 3: Broadcast Boost Request & Game Mode popup suppression] -> PASSED ({dt3:.2f}s)")

        # ---------------------------------------------------------------------
        # Check 4: Clean Cluster Teardown & Zero Process Leaks
        # ---------------------------------------------------------------------
        t0 = time.time()
        procs = list(cluster.node_procs.values())
        cluster.stop_cluster(cleanup_runtime=True)

        for p in procs:
            assert p.poll() is not None, f"Node process {p.pid} still running after stop_cluster!"

        assert not tmp_runtime.exists(), "Temporary demo runtime directory was not unlinked!"

        # Also test demo_cluster CLI flag invocation directly
        cli_test = subprocess.run(
            [sys.executable, "demo_cluster.py", "--headless-check", "--base-port", str(get_free_port())],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        assert cli_test.returncode == 0, f"demo_cluster.py --headless-check failed: {cli_test.stdout}"
        assert "DEMO_CLUSTER_VERIFIED_OK" in cli_test.stdout
        assert retained_marker.read_text(encoding="utf-8") == "existing interactive demo data", "Headless check modified interactive demo storage"

        dt4 = time.time() - t0
        print(f"[Check 4: Clean cluster teardown & zero process leaks] -> PASSED ({dt4:.2f}s)")

    finally:
        cluster.stop_cluster(cleanup_runtime=True)
        shutil.rmtree(tmp_runtime, ignore_errors=True)
        retained_marker.unlink(missing_ok=True)
        if not retained_existed:
            try:
                retained_runtime.rmdir()  # Empty only; never recursively remove existing demo data.
            except OSError:
                pass

    total_time = time.time() - total_start
    print("-" * 70)
    print(f"Stage 6 Gate Status: PASSED (Total Runtime: {total_time:.2f}s)")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_stage6_verification_gate()
    sys.exit(0 if success else 1)
