# LANPool: Cooperative Bandwidth Aggregation & LAN-Cache System
**Master Technical Specification & Staged Implementation Plan (SSOT for OpenCode & Antigravity)**

---

## 1. System Overview & Core Objective
**LANPool** is a headless Python background daemon paired with a real-time Localhost Web UI (`FastAPI` + `HTML/Tailwind/JS`). It is built for **Gaming Cafes, Esports Arenas, and Local Tech Studios** where individual PCs face per-station WAN speed limits (e.g., $2\text{--}10\text{ MB/s}$) while connected to an unthrottled $100\text{ MB/s}$ ($1\text{ Gbps}$) local network.

Every PC on the network runs the **exact same agent** (acting simultaneously as a Requester when the user downloads a file, a Cache Server for previously downloaded files, and a QoS-controlled Helper for peers).

---

## 2. Non-Negotiable Engineering Rules (The 11 Production Safeguards)
All code generated across every stage **must** strictly enforce these 11 architectural invariants:

1. **Dynamic $10\text{ MB}$ Micro-Chunk Queue (No Static Slicing):** Files are sliced into $10\text{ MB}$ ($10,485,760\text{ byte}$) job descriptors stored in an asynchronous work queue. Fast peers pull more jobs; slow peers pull fewer; memory usage never exceeds $10\text{ MB}$ per worker.
2. **Windows NTFS Lock Prevention (`WinError 32` Guard):** Network worker threads **never** open or write directly to the target file on disk. All received chunk bytes are pushed into a thread-safe/async writer queue `(chunk_id, start_byte, raw_bytes)` consumed by a **Single Dedicated Disk-Writer Task** using `file.seek(start_byte)`.
3. **Physical LAN IP Resolution (Virtual Adapter Bypass):** Never use `socket.gethostbyname()`. Always resolve the host's real physical LAN IP by opening a dummy UDP socket (`socket.SOCK_DGRAM`) pointed at `("8.8.8.8", 80)` and reading `s.getsockname()[0]`.
4. **Captive Portal & Error Page Poison Guard (`HTTP 206` Assertion):** Every range request made by the Requester or a Helper must strictly assert `response.status_code == 206` (Partial Content) AND `len(data) == (end_byte - start_byte + 1)`. If a router/server returns `200 OK` (HTML login page) or `403`, discard the payload immediately and requeue the chunk.
5. **CDN Redirect Resolution on Requester Only:** Only the Requester resolves initial URL redirects (`allow_redirects=True`) and extracts the final direct CDN URL, `Content-Length`, `ETag`, and `Accept-Ranges` headers before dispatching chunk jobs to Helpers.
6. **Stale Cache Prevention via `ETag` Verification:** Local LAN-Cache lookups never match by URL string alone. They match against a composite key of `final_url + remote_etag` (or `Last-Modified` if `ETag` is absent).
7. **Zero Path Traversal (`SHA-256` Hash-Only Serving):** The LAN-Cache endpoint (`/api/cache/{sha256}`) only accepts a 64-character hex SHA-256 string and looks up the file path inside an approved in-memory dictionary. Never pass user-supplied filenames or relative paths (`../`) to filesystem calls.
8. **$10\text{ GB}$ Ring-Buffer LRU Cache Eviction:** Before moving a completed download into `LANPool_Cache/`, verify total directory size. Automatically evict the oldest files (by modification time `mtime`) until total size is under the configured quota (default $10\text{ GB}$).
9. **Deep-Freeze / Reboot Resilience:** On daemon startup, automatically scan the configured `LANPool_Cache/` directory, compute/verify SHA-256 hashes of existing `.bin`/cached files, and rebuild `cache_index.json` dynamically.
10. **Pre-Flight Disk Space Check:** Before starting any download, verify `shutil.disk_usage(download_dir).free > (file_size + 100 * 1024 * 1024)`.
11. **Anti-Cheat Safe & Fullscreen Game-Mode Watchdog:** Never import `scapy`, `npcap`, or Layer-2 raw sockets. Use a background `psutil` loop (every $5\text{ seconds}$) to check running process names against a configurable game list (`valorant.exe`, `cs2.exe`, `dota2.exe`, etc., plus a manual UI toggle for testing). When Game Mode is active, suppress all Boost popups and lock helper bandwidth sharing to the passive minimum.

---

## 3. Target Repository Structure
Keep the project modular, clean, and easy to debug:

```text
lanpool/
├── lanpool_master_implementation_plan.md # Single Source of Truth document
├── requirements.txt             # fastapi, uvicorn, httpx, pydantic (Python 3.14+)
├── main.py                      # Entrypoint: starts FastAPI + lifespan background tasks
├── config.py                    # Configurable ports, cache/download dirs, 10MB chunk size, tokens
├── core/
│   ├── __init__.py
│   ├── net_utils.py             # 8.8.8.8 physical LAN IP detector, disk check, interface info
│   ├── url_safety.py            # SSRF protection, hostname resolution, loopback/safe IP validation
│   ├── test_data.py             # Deterministic range-safe mock data generator with LRU caching
│   ├── downloader.py            # Range stream probe, 10MB Micro-Chunk Queue, Single-Thread Disk Writer
│   ├── cache_manager.py         # 10GB true LRU Ring-Buffer, O(1) lookup index, SHA-256 hex store
│   ├── peer_registry.py         # Peer registry (max 256 UDP peers, 15s TTL, manual peers persist)
│   ├── peer_discovery.py        # UDP broadcast sender/listener (port 9999, 3s beacons)
│   ├── worker.py                # Helper HTTP Range fetcher with HTTP 206 assertion and ETag pinning
│   └── watchdog.py              # psutil fullscreen game detector, rate limiter & Boost manager
├── scripts/
│   └── export_state.py          # State exporter & verification gate orchestrator (Stages 1-6)
├── static/
│   └── index.html               # Single-file Dark-Carbon Systems Dashboard UI (Zero-CDN, JetBrains Mono)
├── demo_cluster.py              # One-click 3-node demo cluster + Range-capable throttled origin server
├── README.md                    # Complete architectural guide & 5-minute college viva demo script
├── verify_stage1.py             # Stage 1 verification gate (solo chunked engine)
├── verify_stage2.py             # Stage 2 verification gate (LAN cache engine)
├── verify_stage3.py             # Stage 3 verification gate (UDP discovery + manual peer fallback)
├── verify_stage3_5.py           # Stage 3.5 verification gate (audit remediation: 20 findings)
├── verify_stage4.py             # Stage 4 verification gate (cooperative pooling, cache hits, failover)
├── verify_stage5.py             # Stage 5 verification gate (QoS watchdog, boost protocol, dashboard)
└── verify_stage6.py             # Stage 6 verification gate (3-node cluster, throttled origin, viva suite)
```

---

## 4. Staged Implementation Roadmap

### STAGE 1: Core Solo Download Engine & Single-Thread Disk Writer [SHIPPED]
**Goal:** Build a rock-solid local download manager that slices any direct URL into $10\text{ MB}$ micro-chunks, downloads them concurrently on the local machine, validates `HTTP 206`, writes them safely via a single disk writer thread, and verifies the final SHA-256 hash.
* **Deliverables:**
  * `config.py`, `core/net_utils.py` (IP resolution + disk check), `core/downloader.py`, and basic FastAPI endpoints in `main.py` (`POST /api/download/start`, `GET /api/download/status`).
  * Pre-flight `HTTP HEAD` (with fallback to `GET` `Range: bytes=0-0` if server blocks `HEAD`) extracting `final_url`, `total_size`, `etag`, and `accept_ranges`.
  * Dynamic $10\text{ MB}$ chunk generator (`chunk_id`, `start_byte`, `end_byte`, `status`: `queued | downloading | done | requeued | poisoned`).
  * Single dedicated writer coroutine/thread pulling `(chunk_id, start_byte, data)` from an `asyncio.Queue` and writing to `<filename>.<job_id>.part` using `seek(start_byte)`.
* **Verification Gate 1:** `verify_stage1.py` executes against an ephemeral server, downloads test files with concurrent chunks, verifies SHA-256, and ensures cleanup.

---

### STAGE 2: Security-Hardened $10\text{ GB}$ LRU LAN-Cache Engine [SHIPPED]
**Goal:** Add automatic local caching of completed downloads, startup directory self-indexing, $10\text{ GB}$ LRU eviction, and the Path-Traversal-proof SHA-256 serving endpoint.
* **Deliverables:**
  * `core/cache_manager.py` managing `./LANPool_Cache/`.
  * Startup directory scan that hashes existing files and populates approved hash records with O(1) lookup index mapping `(url, etag)` and `(original_url, etag)`.
  * True LRU eviction loop updating `last_access` on access and evicting oldest access files when quota exceeded.
  * FastAPI endpoints:
    * `GET /api/cache/lookup?url=...&etag=...` $\rightarrow$ returns `{"hit": True, "sha256": "...", "size": ...}` only if both URL and ETag match.
    * `GET /api/cache/stream/{sha256}` $\rightarrow$ validates `sha256` is strictly 64 hex chars and present in approved records, then streams the file at full LAN speed.
* **Verification Gate 2:** `verify_stage2.py` tests T1–T7 (SHA lookup, streaming, path traversal prevention, LRU eviction, boot re-indexing).

---

### STAGE 3: UDP Broadcast Discovery, Firewall Diagnostics & Manual Peer Fallback [SHIPPED]
**Goal:** Enable nodes on the LAN (or different local ports in demo mode) to discover each other automatically via UDP broadcast, while providing a manual IP/Port addition fallback in case Windows Defender Firewall blocks UDP.
* **Deliverables:**
  * `core/peer_discovery.py` & `core/peer_registry.py`:
    * UDP Broadcast listener and sender on port `9999` broadcasting JSON beacons every $3\text{ seconds}$: `{"node_id": "...", "http_port": 8000, "lan_ip": "...", "timestamp": ...}`.
    * In-memory peer registry with $15\text{-second}$ TTL pruning for UDP peers (manual peers persist permanently), timestamp skew guard ($\pm 60\text{s}$ window), and bounded table size (max 256 UDP peers).
  * FastAPI endpoints:
    * `GET /api/peers/list` $\rightarrow$ lists active UDP discovered and manual peers.
    * `POST /api/peers/add` $\rightarrow$ accepts `{"ip": "...", "port": ...}`, probes `GET http://ip:port/api/health`, and adds the peer directly with strict loopback/safe IP validation.
    * `GET /api/diagnostics/network` $\rightarrow$ returns physical LAN IP, interface info, and UDP listener status with error telemetry.
    * `GET /api/health` $\rightarrow$ returns node ID, status, and port.
* **Verification Gate 3:** `verify_stage3.py` runs two ephemeral instances with isolated cache/download dirs, tests 2-way discovery, manual addition fallback, 15s reap TTL, and UDP bind conflict isolation.

---

### STAGE 3.5: Full Audit Remediation & Defense-in-Depth Hardening [SHIPPED]
**Goal:** Address all 20 findings from the architectural audit (`.agents/code_audit.md`) before building multi-node pooling.
* **Remediated Invariants:**
  1. *Bounded Chunk Retries (Finding 1):* Capped at 5 retries per chunk; fail-fast abort on non-Range origin.
  2. *Streamed Probe & Wildcard Rejection (Finding 2):* Zero buffering during probe, reject `Content-Range: bytes 0-0/*`.
  3. *Bounded Writer Queue & Failure Handling (Finding 3):* `maxsize=4`, writer exceptions immediately cancel network workers.
  4. *Per-Job Part Files & 409 Conflict Prevention (Findings 4, 5):* `<filename>.<job_id>.part` isolation, unlinked on failure, 409 on duplicate active targets.
  5. *URL Validation & SSRF Guard (Finding 6):* `core/url_safety.py` validates schemes, resolves hostnames, and blocks dangerous IP ranges.
  6. *Per-Instance Cache & Download Dirs (Finding 7):* Supported via `--cache-dir` and `--download-dir` CLI flags, atomic tmp index writing.
  7. *Independent Test Data Generator (Finding 8):* `core/test_data.py` with `@lru_cache`, 100 MB cap on test endpoints.
  8. *Discovery Security & Peer Deduplication (Findings 9, 10):* 60s timestamp window, IP safety checks, restart deduplication, max 256 peers.
  9. *Concurrency & Task Pruning (Finding 11):* Max 4 active downloads (429 on excess), completed tasks pruned after 50.
  10. *True LRU & O(1) Cache Lookup (Findings 12, 13, 14):* `last_access` tracking, composite index keys for both `original_url` and `final_url`.
  11. *ETag Pinning & Poison Prevention (Finding 15):* `If-Range` pinning on chunks, `RemoteContentChangedError` fails fast.
  12. *Verification Gates & Exporter Hardening (Findings 16, 17, 18, 19, 20):* Isolated temp directories, DEVNULL child process stdout/stderr, dedicated `verify_stage3_5.py` test suite.

---

### STAGE 4: Cooperative Multi-Peer Pooling, Phase-1 Cache Hit & Self-Healing Failover [SHIPPED]
**Goal:** Connect the Requester's $10\text{ MB}$ Micro-Chunk Queue to discovered Helpers so multiple nodes download slices in parallel from the web and stream them to the Requester over LAN, with instant failover if a helper crashes or receives captive-portal poison.
* **Deliverables:**
  * `core/worker.py` and Helper endpoint `POST /api/worker/fetch-chunk`:
    * Receives `{"url": final_url, "start_byte": X, "end_byte": Y, "chunk_id": N}`.
    * Fetches bytes `X-Y` from the upstream URL using the Helper's own network interface.
    * Asserts `HTTP 206` and exact byte length `(Y - X + 1)`.
    * Streams raw binary chunk back to the Requester with header `X-Chunk-SHA256`.
  * Upgrade `core/downloader.py` Coordinator to execute the **2-Phase Flow**:
    * **Phase 1 (LAN-Cache Check):** Query all active peers via `/api/cache/lookup?url=...&etag=...`. If any peer replies `hit: True`, pull the entire file from that peer's `/api/cache/stream/{sha256}` at LAN speed ($100\text{ MB/s}$) and skip WAN downloading.
    * **Phase 2 (Cooperative Micro-Chunk Pool):** Spawn async worker loops for **Self** + each **Active Helper Peer**. Each worker pulls the next `queued` $10\text{ MB}$ chunk from the central queue, requests it from the assigned Helper (`/api/worker/fetch-chunk` with a $8\text{-second}$ timeout), verifies length/hash, and pushes bytes to the Single-Thread Disk Writer.
    * **Self-Healing Requeue:** If a Helper times out, disconnects, or returns `HTTP 200` poison, mark the chunk `requeued` (yellow state for $1\text{ second}$ for UI visibility), push it back into the queue, and let a healthy worker finish it.
* **Verification Gate 4:** Run 3 nodes (`8001`, `8002`, `8003`). Trigger a download on `8001`. Kill node `8003` mid-download (`Ctrl+C`) and verify `8001` and `8002` automatically pick up `8003`'s orphaned $10\text{ MB}$ chunk and produce an uncorrupted final file. Then trigger the exact same URL on `8002` and verify Phase 1 fetches it from `8001`'s LAN cache immediately.

---

### STAGE 5: QoS Speed Limiter, `psutil` Game-Mode Watchdog & Good Samaritan Boost [SHIPPED]
**Goal:** Ensure Helper nodes never lag their owners during gaming or work, while allowing idle users to click a one-button "Boost to 80%" toast notification when a peer downloads a large file.
* **Deliverables:**
  * Token-bucket / chunk-pacing speed limiter inside `core/worker.py`: throttles Helper download streaming to `configured_max_wan_mbps * (current_share_pct / 100.0)`.
  * `core/watchdog.py`:
    * Polls `psutil.process_iter(['name'])` every $5\text{ seconds}$.
    * Includes a manual API toggle (`POST /api/settings/game-mode`) so the user can simulate launching `Valorant.exe` during a live college demo without installing a $40\text{ GB}$ game.
    * When `game_mode == True`, automatically locks `effective_share_pct = min(user_share_pct, 15)` and sets `suppress_popups = True`.
  * Good Samaritan Boost Flow:
    * When a Requester starts a Phase-2 download larger than `BOOST_THRESHOLD_MB`, it broadcasts `POST /api/peers/boost-request` to all peers.
    * Peers with `game_mode == False` queue a pending boost alert for their UI (`GET /api/status` includes `pending_boost_request`).
    * Clicking **`[BOOST TO 80%]`** calls `POST /api/settings/boost` on that Helper, raising its share to $80\%$ for the duration of that job.
* **Verification Gate 5:** Enable Game Mode on Helper `8002` and send a Boost Request from `8001`. Confirm `8002` suppresses the alert and stays at $15\%$ speed, while idle Helper `8003` receives the alert and jumps to $80\%$ speed when accepted.

---

### STAGE 6: High-Craft Dark Web UI Dashboard & Multi-Node Demo Launcher [SHIPPED]
**Goal:** Build the polished single-page Dark UI (`static/index.html`) matching the LANPool mockup, plus a one-command `demo_cluster.py` script and Chaos Simulator buttons for a foolproof college presentation.
* **Deliverables:**
  * `static/index.html` served at `GET /`:
    * **Top Header:** Node Name, Real LAN IP pill, `LAN Traffic: UNISOLATED` badge, `Firewall: ALLOWED` badge, and a quick-switch dropdown or tabs to view peers.
    * **Left Panel (Active LAN Peers & QoS Controls):** Live cards for each discovered peer showing real-time speed, `BOOSTED (Green)` or `PASSIVE Focus Mode (Amber)` badges, manual **"ADD PEER IP:PORT"** box, Bandwidth Sharing `%` slider, and a **"Simulate Fullscreen Game (`Valorant.exe`)"** toggle switch.
    * **Center Panel (Active Download Center):** URL input bar + Start button, live throughput meters (`My WAN MB/s` vs `LAN Pooled MB/s`), real-time speed line chart, and the **Dynamic $10\text{ MB}$ Micro-Chunk Grid** where each block updates color in real time (`Grey` = Queued, `Emerald` = Self, `Blue/Purple` = Specific Helper, `Yellow Pulse` = Re-queued after timeout, `Red` = HTTP 200 Poison Dropped).
    * **Demo Chaos Buttons (Built into UI for Viva Presentation):** Buttons to *"Simulate Helper Crash Mid-Chunk"* and *"Simulate Captive Portal HTTP 200 Poison"* so the evaluator can watch the chunk grid turn yellow/red and self-heal live.
    * **Bottom-Right Panel:** $10\text{ GB}$ Ring-Buffer Storage doughnut chart + SHA-256 verified file list + pop-up **LAN Boost Request Toast** (`[BOOST TO 80%]` / `[KEEP PASSIVE]`).
  * `demo_cluster.py`: Launches 3 nodes on `127.0.0.1:8001`, `8002`, and `8003` plus a local high-speed Range-capable test file generator so the entire multi-peer system can be demonstrated offline on a single laptop or across multiple laptops on a LAN.
* **Verification Gate 6:** Run `python demo_cluster.py`, open `http://127.0.0.1:8001`, run both a Phase-2 Pooled Download and a Phase-1 LAN Cache Hit, trigger the Boost Toast on `http://127.0.0.1:8002`, and test the Chaos buttons.