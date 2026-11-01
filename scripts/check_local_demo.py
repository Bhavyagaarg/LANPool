"""Smoke-test the default demo already running on ports 8001-8003/8090."""
import hashlib
import json
import time
from pathlib import Path
import httpx


def run():
    results = {}
    with httpx.Client(timeout=15, trust_env=False) as client:
        for port in (8001, 8002, 8003):
            base = f"http://127.0.0.1:{port}"
            health = client.get(base + "/api/health")
            health.raise_for_status()
            dashboard = client.get(base + "/")
            dashboard.raise_for_status()
            results[str(port)] = {"health": health.json(), "dashboard_status": dashboard.status_code, "peers": client.get(base + "/api/peers/list").json()["count"]}
        origin_url = "http://127.0.0.1:8090/files/game-update-60mb.pak"
        def download(filename):
            response = client.post("http://127.0.0.1:8001/api/download/start", json={"url": origin_url, "filename": filename})
            response.raise_for_status()
            job = response.json()["job_id"]
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                status = client.get("http://127.0.0.1:8001/api/download/status", params={"job_id": job}).json()
                if status["status"] in ("completed", "failed"):
                    assert status["status"] == "completed", status
                    return status
                time.sleep(0.1)
            raise TimeoutError(job)
        first = download("local-setup-check.pak")
        digest = hashlib.sha256()
        with client.stream("GET", "http://127.0.0.1:8001/api/cache/stream/" + first["sha256"]) as stream:
            stream.raise_for_status()
            for block in stream.iter_bytes():
                digest.update(block)
        assert digest.hexdigest() == first["sha256"]
        second = download("local-setup-cache-check.pak")
        results["download"] = {key: first[key] for key in ("status", "source", "sha256", "total_size", "wan_bytes", "lan_bytes")}
        results["repeat_download"] = {key: second[key] for key in ("status", "source", "sha256", "wan_bytes", "lan_bytes")}
        results["cache"] = client.get("http://127.0.0.1:8001/api/cache/list").json()
        qos_url = "http://127.0.0.1:8002/api/qos/"
        old = client.get(qos_url + "status").json()
        try:
            client.post(qos_url + "update", json={"share_pct": 10, "boosted": False, "throttling_enabled": True}).raise_for_status()
            started = time.perf_counter()
            response = client.post("http://127.0.0.1:8002/api/worker/fetch-chunk", json={"url": origin_url, "start_byte": 0, "end_byte": 10485759, "chunk_id": 0})
            response.raise_for_status()
            results["live_qos_10_percent"] = {"elapsed_seconds": round(time.perf_counter() - started, 3), "bytes": len(response.content), "expected_min_seconds_at_2MiBps": 5}
            assert results["live_qos_10_percent"]["elapsed_seconds"] >= 4.9, "Live helper exceeded its configured byte budget"
        finally:
            client.post(qos_url + "update", json={key: old[key] for key in ("share_pct", "boosted", "simulate_game_mode", "throttling_enabled")}).raise_for_status()
    path = Path(__file__).resolve().parents[1] / "LOCAL_SMOKE_RESULTS.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    run()
