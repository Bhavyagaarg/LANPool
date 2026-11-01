"""Compare equally parallel fresh solo/pooled jobs on a running node.

This measures this topology only; it does not imply additional router uplink capacity.
"""
import argparse
import json
import os
import statistics
import time
from pathlib import Path
import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="http://127.0.0.1:8001")
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", default="benchmark-results.json")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error("repeats must be 1..20")
    samples = {"solo": [], "pooled": []}
    headers = {"X-LANPool-Token": os.environ.get("LANPOOL_API_TOKEN", "")}
    with httpx.Client(timeout=15, trust_env=False, headers=headers) as client:
        for i in range(args.repeats):
            # Alternate order across runs; both modes use the same four-worker ceiling.
            for mode in (("solo", "pooled") if i % 2 == 0 else ("pooled", "solo")):
                started = time.monotonic()
                response = client.post(args.node + "/api/download/start", json={"url": args.url, "filename": f"benchmark-{mode}.bin", "expected_sha256": args.expected_sha256, "use_cache": False, "use_peers": mode == "pooled"})
                response.raise_for_status()
                job_id = response.json()["job_id"]
                deadline = time.monotonic() + 600
                while time.monotonic() < deadline:
                    status = client.get(args.node + "/api/download/status", params={"job_id": job_id}).json()
                    if status["status"] in ("completed", "failed", "cancelled"):
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError(job_id)
                if status["status"] != "completed":
                    raise RuntimeError(status.get("error"))
                if mode == "pooled" and status.get("helper_origin_bytes", 0) == 0:
                    raise RuntimeError("No helper contributed: provide a trusted publisher SHA-256, pair healthy peers, and use a multi-chunk file; refusing to label a solo result as pooled")
                elapsed = time.monotonic() - started
                samples[mode].append({"seconds": round(elapsed, 3), "mibps": round(status["total_size"] / elapsed / 1048576, 3), "source": status["source"], "sha256": status["sha256"], "requester_origin_bytes": status["origin_received_bytes"], "helper_origin_bytes": status["helper_origin_bytes"]})
    summary = {mode: round(statistics.median(sample["seconds"] for sample in runs), 3) for mode, runs in samples.items()}
    report = {"equal_worker_ceiling": 4, "cache_bypassed": True, "median_seconds": summary, "samples": samples, "scope": "Observed topology only; shared-WAN capacity is unchanged. Helper byte totals cover successful chunks, not all retries/wire overhead."}
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
