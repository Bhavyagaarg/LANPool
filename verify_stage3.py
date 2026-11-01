#!/usr/bin/env python3
"""
LANPool Stage 3 Verification Gate Script (verify_stage3.py)
Tests:
1. Spawns two independent nodes on ports 8091 and 8092 with isolated cache/download directories.
2. Asserts distinct node_ids, correct CLI http_ports, and active UDP listeners on port 9999.
3. Verifies automatic UDP broadcast discovery on single host (Rule A, B, C):
   - Node 1 discovers Node 2 (not itself).
   - Node 2 discovers Node 1 (not itself).
4. Verifies UDP peer TTL reaping (15s TTL):
   - Terminates Node 2, confirms Node 1 drops Node 2 after TTL expires.
5. Verifies manual peer addition fallback:
   - Restarts Node 2, adds Node 2 manually via POST /api/peers/add.
   - Asserts manual=True, validation of IP/port (400/422), self-rejection (400),
     and unreachable endpoint handling (502).
6. Verifies network diagnostics endpoint (/api/diagnostics/network).
7. Verifies graceful degradation on UDP bind conflict (foreign process holding 9999).
8. Drains child outputs via DEVNULL (Finding 17) and cleans up processes/tempdirs in finally.
"""

import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-test-group-key-not-for-deployment")

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent
PORT_NODE1 = 8091
PORT_NODE2 = 8092
PORT_NODE3_CONFLICT = 8093


def is_port_in_use(port: int) -> bool:
    """Checks whether a TCP port is currently occupied on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_for_health(port: int, timeout: float = 12.0) -> dict:
    """Polls /api/health until node responds with 200 OK."""
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
        time.sleep(0.2)
    raise TimeoutError(f"Node on port {port} failed to respond at {url} within {timeout}s: {last_err}")


def start_node(
    port: int,
    cache_dir: Optional[str] = None,
    download_dir: Optional[str] = None,
) -> subprocess.Popen:
    """Spawns main.py on the specified port with DEVNULL pipe redirection (Finding 17)."""
    cmd = [sys.executable, "main.py", "--port", str(port)]
    if cache_dir:
        cmd.extend(["--cache-dir", str(cache_dir)])
    if download_dir:
        cmd.extend(["--download-dir", str(download_dir)])

    return subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def terminate_proc(proc: Optional[subprocess.Popen]):
    """Cleanly terminates a child process."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run_stage3_verification() -> bool:
    print("=" * 70)
    print("LANPOOL STAGE 3 VERIFICATION GATE")
    print("Testing UDP Broadcast Discovery, Peer Registry, Manual Fallback & Isolation")
    print("=" * 70)

    for p in (PORT_NODE1, PORT_NODE2, PORT_NODE3_CONFLICT):
        if is_port_in_use(p):
            print(f"FAILED: Port {p} is already in use. Please terminate conflicting processes.")
            return False

    proc_node1: Optional[subprocess.Popen] = None
    proc_node2: Optional[subprocess.Popen] = None
    proc_node3: Optional[subprocess.Popen] = None
    conflict_sock: Optional[socket.socket] = None

    temp_dirs = []

    try:
        # Create isolated cache and download directories per node (Finding 7)
        n1_cache = tempfile.mkdtemp(prefix="lanpool_test_c1_")
        n1_down = tempfile.mkdtemp(prefix="lanpool_test_d1_")
        n2_cache = tempfile.mkdtemp(prefix="lanpool_test_c2_")
        n2_down = tempfile.mkdtemp(prefix="lanpool_test_d2_")
        temp_dirs.extend([n1_cache, n1_down, n2_cache, n2_down])

        # ---------------------------------------------------------------------
        # Step 1: Boot Node 1 (8091) and Node 2 (8092)
        # ---------------------------------------------------------------------
        print(f"\n[Step 1] Starting Node 1 (port {PORT_NODE1}) and Node 2 (port {PORT_NODE2}) with isolated storage...")
        proc_node1 = start_node(PORT_NODE1, cache_dir=n1_cache, download_dir=n1_down)
        proc_node2 = start_node(PORT_NODE2, cache_dir=n2_cache, download_dir=n2_down)

        health1 = wait_for_health(PORT_NODE1)
        health2 = wait_for_health(PORT_NODE2)

        print(f"  Node 1 Health: id={health1['node_id'][:12]}... port={health1['http_port']} stage={health1['stage']} udp={health1['udp_listener']}")
        print(f"  Node 2 Health: id={health2['node_id'][:12]}... port={health2['http_port']} stage={health2['stage']} udp={health2['udp_listener']}")

        assert health1["stage"] in (3, 4, 5), f"Expected stage >= 3, got {health1['stage']}"
        assert health2["stage"] in (3, 4, 5), f"Expected stage >= 3, got {health2['stage']}"
        assert health1["http_port"] == PORT_NODE1, f"Expected port {PORT_NODE1}, got {health1['http_port']}"
        assert health2["http_port"] == PORT_NODE2, f"Expected port {PORT_NODE2}, got {health2['http_port']}"
        assert health1["node_id"] != health2["node_id"], "Node IDs must be unique per startup (Rule A)!"
        assert health1["udp_listener"]["running"] is True, "Node 1 UDP listener is not running!"
        assert health2["udp_listener"]["running"] is True, "Node 2 UDP listener is not running!"
        assert health1["udp_listener"]["port"] == 9999, "Expected UDP discovery port 9999"

        # Verify storage isolation (Finding 7)
        assert Path(n1_cache).exists() and Path(n2_cache).exists()
        assert (Path(n1_cache) / "cache_index.json").exists()
        assert (Path(n2_cache) / "cache_index.json").exists()
        print("  ✓ Identity, ports, storage isolation, and UDP listeners validated.")

        node1_id = health1["node_id"]
        node2_id = health2["node_id"]

        # ---------------------------------------------------------------------
        # Step 2: Automatic UDP Broadcast Discovery
        # ---------------------------------------------------------------------
        print("\n[Step 2] Testing automatic UDP broadcast discovery (waiting up to 12s)...")
        discovery_start = time.time()
        node1_discovered_node2 = False
        node2_discovered_node1 = False
        last_peers1 = []
        last_peers2 = []

        while time.time() - discovery_start < 12.0:
            resp1 = httpx.get(f"http://127.0.0.1:{PORT_NODE1}/api/peers/list", timeout=2.0)
            resp2 = httpx.get(f"http://127.0.0.1:{PORT_NODE2}/api/peers/list", timeout=2.0)

            if resp1.status_code == 200:
                last_peers1 = resp1.json().get("peers", [])
                pids1 = [p.get("node_id") for p in last_peers1]
                if node2_id in pids1:
                    node1_discovered_node2 = True

            if resp2.status_code == 200:
                last_peers2 = resp2.json().get("peers", [])
                pids2 = [p.get("node_id") for p in last_peers2]
                if node1_id in pids2:
                    node2_discovered_node1 = True

            if node1_discovered_node2 and node2_discovered_node1:
                break
            time.sleep(0.5)

        elapsed = round(time.time() - discovery_start, 2)
        print(f"  Discovery status after {elapsed}s: Node1->Node2={node1_discovered_node2}, Node2->Node1={node2_discovered_node1}")
        assert node1_discovered_node2, f"Node 1 failed to discover Node 2 via UDP broadcast: {last_peers1}"
        assert node2_discovered_node1, f"Node 2 failed to discover Node 1 via UDP broadcast: {last_peers2}"

        # Assert no self-echo in peer lists (Rule A)
        pids1 = [p.get("node_id") for p in last_peers1]
        pids2 = [p.get("node_id") for p in last_peers2]
        assert node1_id not in pids1, "Self-echo violation: Node 1 listed itself in peers!"
        assert node2_id not in pids2, "Self-echo violation: Node 2 listed itself in peers!"

        peer_on_node1 = next(p for p in last_peers1 if p.get("node_id") == node2_id)
        assert peer_on_node1["manual"] is False, "UDP peer must have manual=False"
        assert peer_on_node1["source"] == "udp", "UDP peer must have source='udp'"
        assert peer_on_node1["port"] == PORT_NODE2, f"Expected peer port {PORT_NODE2}"
        print(f"  ✓ Cross-discovery confirmed: Node 1 sees Node 2 (port {PORT_NODE2}), Node 2 sees Node 1 (port {PORT_NODE1}).")
        print("  ✓ Rule A validated: Zero self-echo in peer tables.")

        # ---------------------------------------------------------------------
        # Step 3: UDP Peer Reaper & TTL Eviction (15s TTL)
        # ---------------------------------------------------------------------
        print("\n[Step 3] Testing peer TTL reaper: terminating Node 2 and waiting for eviction...")
        terminate_proc(proc_node2)
        proc_node2 = None

        reap_start = time.time()
        reaped = False
        peers = []
        while time.time() - reap_start < 22.0:
            resp = httpx.get(f"http://127.0.0.1:{PORT_NODE1}/api/peers/list", timeout=2.0)
            if resp.status_code == 200:
                peers = resp.json().get("peers", [])
                pids = [p.get("node_id") for p in peers]
                if node2_id not in pids:
                    reaped = True
                    break
            time.sleep(1.0)

        reap_elapsed = round(time.time() - reap_start, 2)
        print(f"  Reaper check: Node 2 reaped from Node 1 in {reap_elapsed}s (TTL=15s)")
        assert reaped, f"Node 2 was not evicted by Node 1's reaper within timeout (last peers: {peers})"
        print("  ✓ TTL eviction verified: silent UDP peer successfully reaped.")

        # ---------------------------------------------------------------------
        # Step 4: Manual Peer Fallback (POST /api/peers/add)
        # ---------------------------------------------------------------------
        print("\n[Step 4] Testing manual peer addition fallback...")
        print(f"  Restarting Node 2 on port {PORT_NODE2}...")
        proc_node2 = start_node(PORT_NODE2, cache_dir=n2_cache, download_dir=n2_down)
        new_health2 = wait_for_health(PORT_NODE2)
        new_node2_id = new_health2["node_id"]
        print(f"  Node 2 restarted with new id={new_node2_id[:12]}...")

        # Test validation of invalid inputs
        bad_ip_resp = httpx.post(f"http://127.0.0.1:{PORT_NODE1}/api/peers/add", json={"ip": "999.999.999.999", "port": PORT_NODE2})
        assert bad_ip_resp.status_code in (400, 422), f"Expected 400/422 for invalid IP, got {bad_ip_resp.status_code}"

        bad_port_resp = httpx.post(f"http://127.0.0.1:{PORT_NODE1}/api/peers/add", json={"ip": "127.0.0.1", "port": 70000})
        assert bad_port_resp.status_code in (400, 422), f"Expected 400/422 for invalid port, got {bad_port_resp.status_code}"

        self_add_resp = httpx.post(f"http://127.0.0.1:{PORT_NODE1}/api/peers/add", json={"ip": "127.0.0.1", "port": PORT_NODE1})
        assert self_add_resp.status_code in (400, 422), f"Expected 400/422 for self-add, got {self_add_resp.status_code}"

        unreachable_resp = httpx.post(f"http://127.0.0.1:{PORT_NODE1}/api/peers/add", json={"ip": "127.0.0.1", "port": 59999})
        assert unreachable_resp.status_code == 502, f"Expected 502 for unreachable peer, got {unreachable_resp.status_code}"
        print("  ✓ Validation checks passed (invalid IP -> 400, invalid port -> 400, self-add -> 400, unreachable -> 502).")

        # Valid manual addition
        add_resp = httpx.post(
            f"http://127.0.0.1:{PORT_NODE1}/api/peers/add",
            json={"ip": "127.0.0.1", "port": PORT_NODE2},
            timeout=5.0,
        )
        assert add_resp.status_code == 200, f"Expected 200, got {add_resp.status_code}: {add_resp.text}"
        added_peer = add_resp.json()
        assert added_peer["manual"] is True, "Manual peer must have manual=True"
        assert added_peer["source"] == "manual", "Manual peer must have source='manual'"
        assert added_peer["port"] == PORT_NODE2, f"Expected port {PORT_NODE2}"
        print(f"  ✓ Manual add returned 200 OK: peer={added_peer['node_id'][:12]}... manual={added_peer['manual']}")

        # Verify presence in list_peers
        list_resp = httpx.get(f"http://127.0.0.1:{PORT_NODE1}/api/peers/list")
        assert list_resp.status_code == 200
        peers_list = list_resp.json().get("peers", [])
        manual_match = next((p for p in peers_list if p.get("port") == PORT_NODE2), None)
        assert manual_match is not None, f"Node 2 not found in Node 1 peers list: {peers_list}"
        assert manual_match["manual"] is True
        print("  ✓ Manual peer confirmed present in /api/peers/list.")

        # ---------------------------------------------------------------------
        # Step 5: Network Diagnostics Endpoint
        # ---------------------------------------------------------------------
        print("\n[Step 5] Testing network diagnostics (/api/diagnostics/network)...")
        diag_resp = httpx.get(f"http://127.0.0.1:{PORT_NODE1}/api/diagnostics/network", timeout=2.0)
        assert diag_resp.status_code == 200, f"Expected 200 from diagnostics, got {diag_resp.status_code}"
        diag = diag_resp.json()

        assert diag["udp"]["listener_running"] is True, "Diagnostics reports UDP listener not running"
        assert diag["udp"]["port"] == 9999, f"Diagnostics reports wrong UDP port: {diag['udp']['port']}"
        assert "255.255.255.255" in diag["udp"]["broadcast_targets"], "Missing 255.255.255.255 in broadcast targets"
        assert "127.255.255.255" in diag["udp"]["broadcast_targets"], "Missing 127.255.255.255 in broadcast targets"
        assert diag["udp"]["beacon_interval_seconds"] == 3.0, "Expected beacon interval 3.0s"
        assert diag["peers"]["total"] >= 1, "Expected at least 1 total peer in diagnostics"
        assert diag["peers"]["manual"] >= 1, "Expected at least 1 manual peer in diagnostics"
        assert diag["peers"]["stale_after_seconds"] == 15.0, "Expected stale_after_seconds == 15.0"
        assert len(diag.get("firewall_hint", "")) > 0, "Expected non-empty firewall_hint"
        print(f"  ✓ Diagnostics verified: udp_running={diag['udp']['listener_running']}, peers={diag['peers']}, targets={diag['udp']['broadcast_targets']}")

        # ---------------------------------------------------------------------
        # Step 6: Graceful Degradation on Foreign UDP Bind Conflict (Finding 18)
        # ---------------------------------------------------------------------
        print("\n[Step 6] Testing UDP port 9999 conflict handling & graceful degradation...")
        # Cleanly stop existing nodes to free port 9999 for exclusive foreign bind
        terminate_proc(proc_node1)
        terminate_proc(proc_node2)
        proc_node1 = None
        proc_node2 = None
        time.sleep(0.5)

        # Bind exclusive foreign UDP socket on 9999 without SO_REUSEPORT
        conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conflict_sock.bind(("0.0.0.0", 9999))

        n3_cache = tempfile.mkdtemp(prefix="lanpool_test_c3_")
        n3_down = tempfile.mkdtemp(prefix="lanpool_test_d3_")
        temp_dirs.extend([n3_cache, n3_down])

        proc_node3 = start_node(PORT_NODE3_CONFLICT, cache_dir=n3_cache, download_dir=n3_down)
        health3 = wait_for_health(PORT_NODE3_CONFLICT)

        assert health3["status"] == "online", "Node 3 failed to start in degraded mode"
        assert health3["udp_listener"]["running"] is False, "Node 3 should report udp_listener.running == False"

        diag3_resp = httpx.get(f"http://127.0.0.1:{PORT_NODE3_CONFLICT}/api/diagnostics/network", timeout=2.0)
        assert diag3_resp.status_code == 200
        diag3 = diag3_resp.json()
        assert diag3["udp"]["listener_running"] is False
        assert diag3["udp"]["last_error"] is not None and len(diag3["udp"]["last_error"]) > 0

        # Start peer node for manual fallback test
        n1_cache_deg = tempfile.mkdtemp(prefix="lanpool_test_c1_deg_")
        n1_down_deg = tempfile.mkdtemp(prefix="lanpool_test_d1_deg_")
        temp_dirs.extend([n1_cache_deg, n1_down_deg])
        proc_node1 = start_node(PORT_NODE1, cache_dir=n1_cache_deg, download_dir=n1_down_deg)
        wait_for_health(PORT_NODE1)

        # Manual peer add still works on degraded node
        add_fallback = httpx.post(
            f"http://127.0.0.1:{PORT_NODE3_CONFLICT}/api/peers/add",
            json={"ip": "127.0.0.1", "port": PORT_NODE1},
            timeout=5.0,
        )
        assert add_fallback.status_code == 200
        assert add_fallback.json()["manual"] is True
        print("  ✓ Graceful degradation confirmed: daemon online, udp_running=False, error recorded, manual fallback works.")

        print("\n" + "=" * 70)
        print("STAGE 3 VERIFICATION PASSED: All 6 check suites successful!")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"\nSTAGE 3 VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        print("\n[Teardown] Cleaning up child processes and temporary directories...")
        if conflict_sock:
            try:
                conflict_sock.close()
            except Exception:
                pass
        terminate_proc(proc_node1)
        terminate_proc(proc_node2)
        terminate_proc(proc_node3)
        for td in temp_dirs:
            shutil.rmtree(td, ignore_errors=True)
        print("  ✓ Cleanup complete.")


if __name__ == "__main__":
    success = run_stage3_verification()
    sys.exit(0 if success else 1)
