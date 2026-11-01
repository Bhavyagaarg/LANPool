# LANPool — Known Issues

**Audit date:** 2026-11-01  
**Status:** Stages 1–4 and 6 pass their gates. Stage 5's QoS state machine, UI, and
telemetry exist, but the speed limiter and automatic boost flow are not functionally
enforced. The Stage 5/6 gates assert state labels, not throughput, so their PASSED
status does not cover the items below.

## Critical

### 1. QoS speed limiter does not limit throughput

- `core/watchdog.py::throttle_bytes()` caps every sleep at `0.05s`:
  `delay = min(num_bytes / max(rate, 1024), 0.05)`.
- `main.py::worker_fetch_chunk()` calls it once with the full 10 MB chunk **after**
  `fetch_chunk_from_origin()` has already downloaded the chunk.
- `throttling_enabled` defaults to `False`; `static/index.html` never sends it.
- Result: the share slider and Game Mode cap change labels only.

Measured with an independent probe (10 MB chunk, 20 MB/s base capacity):

| Setting | Expected | Measured |
|---|---|---|
| 10% share | ~5.0 s | **0.135 s** |
| Game Mode 15% | ~3.3 s | **0.106 s** |

Files: `core/watchdog.py`, `main.py`, `static/index.html`, `config.py`.

### 2. Good Samaritan boost is not triggered automatically

- `config.py` has no `BOOST_THRESHOLD_MB`.
- Nothing in `core/downloader.py` calls `/api/qos/boost-request`.
- `demo_cluster.py` broadcasts the boost manually.
- Measured: a 25 MB Phase-2 download on node A produced no boost request on peer B.
- Plan contract: auto-broadcast when a Phase-2 download exceeds `BOOST_THRESHOLD_MB`.

### 3. Stage 5 gate is false-green for the QoS contract

- `verify_stage5.py` checks state transitions and HTML strings, never actual throughput.
- `verify_stage6.py` checks `effective_share_pct == 15/80`, never that transfers slow down.
- A gate pass therefore does not prove the Stage 5 goal ("never lag their owners").

## High

### 4. Boost is permanent, not job-scoped

- `respond_to_boost("boost")` sets `share_pct = 80` and leaves it there.
- The plan says "for the duration of that job". No reset on job completion or TTL.

### 5. Throttling is off by default and not exposed in the UI

- `main.py` constructs `NodeQoSManager()` with `throttling_enabled=False`.
- The UI slider and Game Mode toggle never send `throttling_enabled`.
- Even after fixing the limiter, the default daemon will not throttle.

## Medium

### 6. Plan/README overclaim

- `README.md` says Game Mode "hard-clamps sharing to <= 15%" and "caps sharing".
- `lanpool_master_implementation_plan.md` names `/api/settings/game-mode`,
  `/api/peers/boost-request`, and `/api/status`; the implementation uses
  `/api/qos/update`, `/api/qos/boost-request`, and `/api/qos/status`.
- `.agents/board.md` says Stage 6 is APPROVED but has no Stage 5/6 evidence section;
  its detailed content still ends at Stage 4.

### 7. Watchdog real-process path is untested

- Gates only use `simulate_game_mode`. `check_game_processes()` is never exercised
  against a real process named `valorant.exe` / `cs2.exe`.

### 8. Shutdown nit

- `NodeQoSManager.stop()` cancels `_loop_task` but does not await it.

## Low

### 9. Repo hygiene

- No `.gitignore`; no git repository initialized.
- Runtime/generated artifacts: `LANPool_Cache/` (36 MB), `graphify-out/` (6.3 MB),
  `__pycache__/`, `demo_runtime/`, `PROJECT_STATE.md` (422 KB).
- `requirements.txt` lacks a trailing newline.

## Not affected

Stages 1/2/3/3.5/4 gates pass; download, cache, discovery, pooling, and failover paths
are functional. The Stage 6 demo cluster and UI work; the issue is the QoS speed claim,
not the demo flow.

## Reproduction

1. Start a node with isolated dirs.
2. `POST /api/qos/update {"throttling_enabled": true, "share_pct": 10}`.
3. `POST /api/worker/fetch-chunk` for a 10 MB range from a Range-capable origin.
4. Measure elapsed time: ~5 s expected at 10% of 20 MB/s; observed ~0.1 s.
5. Repeat with `{"share_pct": 100, "simulate_game_mode": true}`: ~3.3 s expected;
   observed ~0.1 s.
6. Start a 25 MB Phase-2 download on node A with node B as a peer; B's
   `/api/qos/status` never shows an `active_boost_request`.

## Suggested fix order (not implemented)

1. Pace the origin stream in `core/worker.py` in 64 KB pieces, with no 0.05 s cap.
2. Default throttling on and expose it through the UI/config.
3. Add `BOOST_THRESHOLD_MB` and auto-broadcast from `core/downloader.py`.
4. Make boost job-scoped instead of permanent.
5. Strengthen `verify_stage5.py` to measure throughput and auto-broadcast.
