#!/usr/bin/env python3
"""
LANPool Stage 5 Verification Gate Script (verify_stage5.py)
Tests QoS Watchdog, Good Samaritan Boost, Telemetry & Web Dashboard:
1. QoS State Management:
   - GET /api/qos/status returns default fields.
   - POST /api/qos/update updates share_pct, validates boundaries (0..100).
   - POST /api/qos/update with boosted=True sets effective_share_pct=80.
   - API token enforcement on protected QoS endpoints.
2. Game Mode Watchdog & Popup Suppression (Safeguard #11):
   - simulate_game_mode=True sets effective_game_mode=True and caps effective_share_pct <= 15.
   - Boost notifications sent during game mode are suppressed (accepted=False, reason="game_mode_silent").
   - active_boost_request remains None.
3. Good Samaritan Boost Flow:
   - simulate_game_mode=False allows boost notification (accepted=True).
   - active_boost_request is populated.
   - POST /api/qos/boost-respond with 'boost' flips boosted=True, share_pct=80, and clears request.
   - Dismiss action clears active request without changing settings.
4. UDP Beacon QoS Propagation:
   - Beacon carries QoS fields (share_pct, game_mode, boosted).
   - Peer node receives beacon and surfaces QoS flags in /api/peers/list.
5. Web Dashboard UI & Telemetry:
   - GET / serves precision systems engineering dashboard (HTML 200).
   - Contains core UI elements: chunk grid, speed chart canvas, peer list, boost toast.
   - Download status exposes telemetry fields (source, wan_bytes, lan_bytes, wan_speed_mbps, lan_speed_mbps).
"""

import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent


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
    """Cleanly terminates and awaits child process exit."""
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


def check1_qos_state_management():
    """Check 1: QoS state management and boundary validation."""
    port = get_free_port()
    udp_port = free_udp_port()
    td = tempfile.mkdtemp(prefix="lanpool_s5_c1_")
    c_dir = Path(td) / "cache"
    d_dir = Path(td) / "downloads"
    token = "secret_qos_token_123"

    proc = None
    try:
        proc = start_node(
            port,
            c_dir,
            d_dir,
            env_extra={"LANPOOL_UDP_PORT": str(udp_port), "LANPOOL_API_TOKEN": token},
        )
        wait_for_health(port)

        url_status = f"http://127.0.0.1:{port}/api/qos/status"
        url_update = f"http://127.0.0.1:{port}/api/qos/update"
        headers = {"X-LANPool-Token": token}

        # 1. Without token -> 401
        r_unauth = httpx.get(url_status, timeout=2.0)
        assert r_unauth.status_code == 401, f"Expected 401 without token, got {r_unauth.status_code}"

        # 2. With token -> 200, default state
        r = httpx.get(url_status, headers=headers, timeout=2.0)
        assert r.status_code == 200, f"Expected 200 with token, got {r.status_code}"
        data = r.json()
        assert data.get("share_pct") == 30, f"Expected default share_pct=30, got {data.get('share_pct')}"
        assert data.get("effective_share_pct") == 30
        assert data.get("boosted") is False
        assert data.get("game_mode") is False
        assert data.get("simulate_game_mode") is False
        assert data.get("effective_game_mode") is False

        # 3. Update share_pct to 60 -> 200
        r_up = httpx.post(url_update, json={"share_pct": 60}, headers=headers, timeout=2.0)
        assert r_up.status_code == 200, f"Expected 200 for update, got {r_up.status_code}"
        up_data = r_up.json()
        assert up_data.get("share_pct") == 60
        assert up_data.get("effective_share_pct") == 60

        # 4. Boundary validation (< 0 or > 100) -> 400
        r_neg = httpx.post(url_update, json={"share_pct": -5}, headers=headers, timeout=2.0)
        assert r_neg.status_code == 400, f"Expected 400 for share_pct < 0, got {r_neg.status_code}"

        r_over = httpx.post(url_update, json={"share_pct": 105}, headers=headers, timeout=2.0)
        assert r_over.status_code == 400, f"Expected 400 for share_pct > 100, got {r_over.status_code}"

        # 5. Boosted=True -> effective_share_pct=80
        r_boost = httpx.post(url_update, json={"boosted": True}, headers=headers, timeout=2.0)
        assert r_boost.status_code == 200
        boost_data = r_boost.json()
        assert boost_data.get("boosted") is True
        assert boost_data.get("effective_share_pct") == 80

    finally:
        terminate_proc(proc)
        shutil.rmtree(td, ignore_errors=True)


def check2_game_mode_suppression():
    """Check 2: Game Mode Watchdog & Popup Suppression (Safeguard #11)."""
    port = get_free_port()
    udp_port = free_udp_port()
    td = tempfile.mkdtemp(prefix="lanpool_s5_c2_")
    c_dir = Path(td) / "cache"
    d_dir = Path(td) / "downloads"

    proc = None
    try:
        proc = start_node(port, c_dir, d_dir, env_extra={"LANPOOL_UDP_PORT": str(udp_port)})
        wait_for_health(port)

        url_status = f"http://127.0.0.1:{port}/api/qos/status"
        url_update = f"http://127.0.0.1:{port}/api/qos/update"
        url_notify = f"http://127.0.0.1:{port}/api/qos/boost-notify"

        # 1. Set share_pct=70, boosted=True, then enable simulate_game_mode=True
        httpx.post(url_update, json={"share_pct": 70, "boosted": True}, timeout=2.0)
        r_gm = httpx.post(url_update, json={"simulate_game_mode": True}, timeout=2.0)
        assert r_gm.status_code == 200
        data = r_gm.json()
        assert data.get("effective_game_mode") is True
        assert data.get("effective_share_pct") == 15, f"Expected 15% Game Mode cap, got {data.get('effective_share_pct')}"
        assert data.get("boosted") is False

        # 2. Incoming boost notification must be suppressed/silenced
        notify_payload = {
            "requester_id": "test_peer_requester_1",
            "requester_ip": "127.0.0.1",
            "filename": "patch_v2.iso",
            "total_size": 104857600,
        }
        r_notif = httpx.post(url_notify, json=notify_payload, timeout=2.0)
        assert r_notif.status_code == 200
        notif_data = r_notif.json()
        assert notif_data.get("accepted") is False, "Expected boost request to be rejected in Game Mode!"
        assert notif_data.get("reason") == "game_mode_silent"

        # 3. Assert active_boost_request remains None
        r_stat = httpx.get(url_status, timeout=2.0)
        assert r_stat.json().get("active_boost_request") is None

    finally:
        terminate_proc(proc)
        shutil.rmtree(td, ignore_errors=True)


def check3_boost_flow():
    """Check 3: Good Samaritan Boost notification & response protocol."""
    port = get_free_port()
    udp_port = free_udp_port()
    td = tempfile.mkdtemp(prefix="lanpool_s5_c3_")
    c_dir = Path(td) / "cache"
    d_dir = Path(td) / "downloads"

    proc = None
    try:
        proc = start_node(port, c_dir, d_dir, env_extra={"LANPOOL_UDP_PORT": str(udp_port)})
        wait_for_health(port)

        url_status = f"http://127.0.0.1:{port}/api/qos/status"
        url_notify = f"http://127.0.0.1:{port}/api/qos/boost-notify"
        url_respond = f"http://127.0.0.1:{port}/api/qos/boost-respond"

        # 1. Send boost notification when Game Mode is inactive
        payload = {
            "requester_id": "peer_node_abc123",
            "requester_ip": "192.168.1.105",
            "filename": "cs2_update.pak",
            "total_size": 52428800,
        }
        r_notif = httpx.post(url_notify, json=payload, timeout=2.0)
        assert r_notif.status_code == 200
        assert r_notif.json().get("accepted") is True

        # 2. Verify active_boost_request is populated
        r_stat = httpx.get(url_status, timeout=2.0)
        active_req = r_stat.json().get("active_boost_request")
        assert active_req is not None
        assert active_req.get("requester_id") == "peer_node_abc123"
        assert active_req.get("filename") == "cs2_update.pak"

        # 3. Accept boost: POST /api/qos/boost-respond {"action": "boost"}
        r_resp = httpx.post(url_respond, json={"action": "boost"}, timeout=2.0)
        assert r_resp.status_code == 200
        resp_data = r_resp.json()
        assert resp_data.get("status") == "boosted"
        assert resp_data.get("effective_share_pct") == 80

        # Verify state updated and active_boost_request cleared
        r_stat2 = httpx.get(url_status, timeout=2.0)
        st2 = r_stat2.json()
        assert st2.get("boosted") is True
        assert st2.get("effective_share_pct") == 80
        assert st2.get("active_boost_request") is None

        # 4. Test dismiss action
        httpx.post(url_notify, json=payload, timeout=2.0)
        r_dism = httpx.post(url_respond, json={"action": "dismiss"}, timeout=2.0)
        assert r_dism.status_code == 200
        assert r_dism.json().get("status") == "dismissed"
        r_stat3 = httpx.get(url_status, timeout=2.0)
        assert r_stat3.json().get("active_boost_request") is None

    finally:
        terminate_proc(proc)
        shutil.rmtree(td, ignore_errors=True)


def check4_udp_beacon_qos_propagation():
    """Check 4: UDP Beacon QoS propagation between nodes."""
    port_a = get_free_port()
    port_b = get_free_port()
    shared_udp = free_udp_port()

    td_a = tempfile.mkdtemp(prefix="lanpool_s5_c4_a_")
    td_b = tempfile.mkdtemp(prefix="lanpool_s5_c4_b_")

    proc_a = None
    proc_b = None

    try:
        proc_a = start_node(
            port_a,
            Path(td_a) / "cache",
            Path(td_a) / "dl",
            env_extra={"LANPOOL_UDP_PORT": str(shared_udp)},
        )
        proc_b = start_node(
            port_b,
            Path(td_b) / "cache",
            Path(td_b) / "dl",
            env_extra={"LANPOOL_UDP_PORT": str(shared_udp)},
        )

        h_a = wait_for_health(port_a)
        h_b = wait_for_health(port_b)
        node_b_id = h_b["node_id"]

        # Boost Node B
        httpx.post(
            f"http://127.0.0.1:{port_b}/api/qos/update",
            json={"boosted": True, "share_pct": 80},
            timeout=2.0,
        )

        # Wait for UDP discovery beacon (up to 8.0s)
        found = False
        start = time.time()
        while time.time() - start < 8.0:
            try:
                r = httpx.get(f"http://127.0.0.1:{port_a}/api/peers/list", timeout=1.0)
                if r.status_code == 200:
                    data = r.json()
                    peers = data.get("peers", []) if isinstance(data, dict) else data
                    match = next((p for p in peers if p.get("node_id") == node_b_id), None)
                    if match and (match.get("boosted") is True or match.get("share_pct") == 80):
                        found = True
                        break
            except Exception:
                pass
            time.sleep(0.3)

        assert found, f"Node A did not observe Node B's boosted QoS flag in /api/peers/list within 8s!"

    finally:
        terminate_proc(proc_a)
        terminate_proc(proc_b)
        shutil.rmtree(td_a, ignore_errors=True)
        shutil.rmtree(td_b, ignore_errors=True)


def check5_web_ui_and_telemetry():
    """Check 5: Web UI static serving and download telemetry fields."""
    port = get_free_port()
    udp_port = free_udp_port()
    td = tempfile.mkdtemp(prefix="lanpool_s5_c5_")
    c_dir = Path(td) / "cache"
    d_dir = Path(td) / "downloads"

    proc = None
    try:
        proc = start_node(port, c_dir, d_dir, env_extra={"LANPOOL_UDP_PORT": str(udp_port)})
        wait_for_health(port)

        # 1. Fetch Web UI at GET /
        resp_ui = httpx.get(f"http://127.0.0.1:{port}/", timeout=3.0)
        assert resp_ui.status_code == 200, f"Expected 200 for dashboard UI, got {resp_ui.status_code}"
        assert "text/html" in resp_ui.headers.get("content-type", "")
        html_text = resp_ui.text

        # Verify core UI functional components are present
        assert "speedChart" in html_text, "Missing speed chart canvas in Web UI!"
        assert "chunk-matrix" in html_text, "Missing 10MB chunk matrix in Web UI!"
        assert "peer-list-container" in html_text, "Missing peer list container in Web UI!"
        assert "boost-toast" in html_text, "Missing Good Samaritan boost toast in Web UI!"
        assert "Simulate Fullscreen Game" in html_text, "Missing Game Mode simulation toggle button!"

        # 2. Trigger a 1 MB test download and verify telemetry fields
        dl_url = f"http://127.0.0.1:{port}/api/test-file/1"
        r_start = httpx.post(
            f"http://127.0.0.1:{port}/api/download/start",
            json={"url": dl_url, "filename": "telemetry_test.bin"},
            timeout=3.0,
        )
        assert r_start.status_code == 200, f"Expected 200 for download start, got {r_start.status_code}"
        job_id = r_start.json()["job_id"]

        # Wait for completion
        completed = False
        data_status = {}
        start = time.time()
        while time.time() - start < 10.0:
            r_st = httpx.get(f"http://127.0.0.1:{port}/api/download/status?job_id={job_id}", timeout=1.0)
            if r_st.status_code == 200:
                data_status = r_st.json()
                if data_status.get("status") == "completed":
                    completed = True
                    break
            time.sleep(0.2)

        assert completed, f"Download {job_id} did not reach completed state within 10s: {data_status}"

        # Assert Stage 5 Telemetry fields
        assert "source" in data_status, "Missing 'source' telemetry field in status!"
        assert data_status["source"] in ("solo", "pooled", "local_cache", "peer_cache")
        assert "wan_bytes" in data_status, "Missing 'wan_bytes' telemetry field!"
        assert "lan_bytes" in data_status, "Missing 'lan_bytes' telemetry field!"
        assert "wan_speed_mbps" in data_status, "Missing 'wan_speed_mbps' telemetry field!"
        assert "lan_speed_mbps" in data_status, "Missing 'lan_speed_mbps' telemetry field!"
        assert data_status["downloaded_bytes"] == 1048576, f"Expected 1048576 bytes, got {data_status['downloaded_bytes']}"

    finally:
        terminate_proc(proc)
        shutil.rmtree(td, ignore_errors=True)


def run_stage5_verification_gate() -> bool:
    """Executes all Stage 5 verification checks sequentially."""
    print("======================================================================")
    print("LANPool Stage 5 Verification Gate: QoS Watchdog, Boost & Web Dashboard")
    print("======================================================================")

    checks = [
        ("Check 1: QoS state management & boundary validation", check1_qos_state_management),
        ("Check 2: Game Mode Watchdog & Popup Suppression", check2_game_mode_suppression),
        ("Check 3: Good Samaritan Boost notification & response", check3_boost_flow),
        ("Check 4: UDP Beacon QoS propagation between nodes", check4_udp_beacon_qos_propagation),
        ("Check 5: Web UI static serving & download telemetry", check5_web_ui_and_telemetry),
    ]

    gate_start = time.time()
    for name, fn in checks:
        t0 = time.time()
        try:
            fn()
            elapsed = time.time() - t0
            print(f"[{name}] -> PASSED ({elapsed:.2f}s)")
        except Exception as e:
            elapsed = time.time() - t0
            print(f"[{name}] -> FAILED ({elapsed:.2f}s): {e}")
            return False

    total_time = time.time() - gate_start
    print("----------------------------------------------------------------------")
    print(f"Stage 5 Gate Status: PASSED (Total Runtime: {total_time:.2f}s)")
    print("======================================================================")
    return True


if __name__ == "__main__":
    success = run_stage5_verification_gate()
    sys.exit(0 if success else 1)
