# LANPool — Cooperative LAN Bandwidth-Aggregation & Cache Daemon

> **Computer Networks Capstone Project**  
> *A decentralized, peer-to-peer cooperative download accelerator and 10 GB ring-buffer cache daemon for local area networks (campus dorms, computer labs, and gaming cafes).*

---

## 🚀 Executive Summary

In high-density environments like college dormitories, computer labs, and gaming centers, internet connectivity (WAN) is often throttled, capped, or congested, while local network bandwidth (LAN) over Gigabit Ethernet and Wi-Fi 6 is fast and virtually free. When multiple users download the same 30–60 GB game patch, operating system ISO, or developer toolchain, each workstation independently saturates the WAN connection.

**LANPool** solves this by pooling idle neighbor bandwidth and local caches:
1. **Cooperative Chunk Slicing:** Large files are sliced into dynamic 10 MB micro-chunks. Nearby idle LAN peers download complementary chunks from upstream CDNs in parallel, aggregating multiple WAN links into a single accelerated stream.
2. **True-LRU Ring-Buffer LAN Cache:** Completed files are indexed by `(URL, ETag)` and SHA-256 in a 10 GB cache. Subsequent downloads of the same file by any workstation complete near-instantaneously over Gigabit LAN with **0 WAN bytes used**.
3. **QoS Watchdog & Game Focus Mode:** Station bandwidth is protected: active fullscreen gaming processes (`Valorant`, `CS2`, `Dota 2`, etc.) are detected every 5 seconds. Game Mode caps the reported share to $\le 15\%$ and suppresses all notification popups, while idle stations can grant a one-click **Good Samaritan Boost** up to 80%.

> **Known issues:** The QoS share percentages are currently state/UI values; the speed limiter and automatic boost trigger are not yet enforced. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the audit and evidence.

---

## 📐 System Architecture: The 3-Phase Coordinator

When a download is requested on any node, the `SoloDownloadTask` coordinator proceeds through three distinct phases:

```
              ┌────────────────────────────────────────────────────────┐
              │           User Requests File via API / Web UI          │
              └───────────────────────────┬────────────────────────────┘
                                          │
                                   [Probe Upstream]
                         Validates Range support & ETag
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   ▼                                             ▼
          [Phase 1a: Local Cache]                       [Phase 1b: Peer Cache]
          URL + ETag exists in local                    Query LAN peers via UDP/HTTP.
          10 GB ring buffer?                            Stream directly at 1 Gbps LAN.
                   │                                             │
               (HIT: 0 WAN)                                  (HIT: 0 WAN)
                   │                                             │
                   └──────────────────────┬──────────────────────┘
                                          ▼ (MISS)
                              [Phase 2: Multi-Peer Pooling]
                    Worker Pool: Self Workers + Helper LAN Workers
                    • Slices target into dynamic 10 MB micro-chunks
                    • Helper workers fetch chunks via helper nodes
                    • Dedicated single async disk-writer task
                    • Self-healing: mid-chunk helper failure re-queued
```

---

## 🛡️ The 11 Engineering Safeguards

| # | Safeguard | Description | Implementation Module |
|---|---|---|---|
| **1** | **Dynamic Micro-Chunk Slicing** | Divides large binary files into fixed 10 MB micro-chunks (`CHUNK_SIZE = 10_485_760`) with exact HTTP Range header negotiation. | `core/downloader.py` |
| **2** | **Micro-Chunk Pre-Allocation** | Pre-flight disk space check requiring `file_size + 100 MB` buffer before any network workers spawn; rejects before chunk allocation. | `core/downloader.py` |
| **3** | **Physical LAN IP Routing Probe** | Connects a non-blocking UDP routing probe (`8.8.8.8:80`) to discover the true physical LAN interface, dropping internal bridge/virtual adapters. | `core/net_utils.py` |
| **4** | **UDP Broadcast Discovery** | Broadcasts JSON beacons every 3s on port 9999 (`255.255.255.255` & `127.255.255.255`) with `SO_REUSEPORT` socket reuse. | `core/peer_discovery.py` |
| **5** | **Decentralized Peer Registry** | 15s TTL reaper thread with automatic self-echo drop (`node_id`), ±60s clock skew defense, and max 256-peer registry bounds. | `core/peer_registry.py` |
| **6** | **ETag Composite Verification** | $O(1)$ composite `(url, normalized_etag)` dictionary lookup preventing stale cache serving across remote CDN file updates. | `core/cache_manager.py` |
| **7** | **Zero Path Traversal** | Strict 64-character lowercase hexadecimal regex validation (`^[0-9a-f]{64}$`) blocking directory traversal attacks (`..%2F`, `..\`). | `core/cache_manager.py` |
| **8** | **10 GB True-LRU Ring Buffer** | Tracks `last_access` timestamps; evicts oldest files when cache exceeds 10 GB quota; atomic `.tmp` index persistence. | `core/cache_manager.py` |
| **9** | **Reboot Resilience Fast Boot-Scan** | Cold-boot scanner trusts `(filename, size, mtime_ns)` to re-index 10 GB of files in <50ms without hashing disk contents. | `core/cache_manager.py` |
| **10** | **Self-Healing Failover** | Failed helper chunks automatically increment `retries`, re-queue with 0.3s backoff; maximum 5 bounded retries before job failure. | `core/downloader.py` |
| **11** | **QoS Watchdog & Game Focus Mode** | Scans `psutil` every 5s for competitive games; caps the reported share to $\le 15\%$ and suppresses popups when game active. Throughput enforcement is tracked in `KNOWN_ISSUES.md`. | `core/watchdog.py` |

---

## 💻 Quickstart: Installation

### Prerequisites
- Python 3.10+ (tested on Python 3.11, 3.12, 3.13, 3.14 on Linux, macOS, and Windows)
- Modern web browser (Chrome, Firefox, Safari, Edge)

```bash
# 1. Clone repository
git clone https://github.com/bhavyagarg/LANPool.git
cd "LANPool"

# 2. Install dependencies
pip install -r requirements.txt
```

---

## 🎮 Mode 1: One-Click 3-Node Live Demo (Single PC)

To demonstrate LANPool on a single laptop or viva presentation screen, run:

```bash
python3 demo_cluster.py
```

This single command launches:
- **Throttled Demo Origin Server (`:8090`):** Simulates a remote game CDN with Range-capable 206 serving for `game-update-60mb.pak`, `ubuntu-patch-35mb.iso`, and `driver-bundle-20mb.bin`.
- **Node 1 (`:8001`):** Primary Requester PC (Default 30% sharing).
- **Node 2 (`:8002`):** Idle Helper PC (Boosted 80% Good Samaritan mode).
- **Node 3 (`:8003`):** Gaming Helper PC (Simulated fullscreen game active, clamped to 15% passive share).

The web dashboard for Node 1 opens automatically in your browser:  
👉 **`http://127.0.0.1:8001`**

*(To exit, press `Ctrl+C` in your terminal. All background nodes and origin processes terminate cleanly with zero leaks).*

---

## 🌐 Mode 2: Multi-Laptop Real Physical LAN Setup

To run LANPool across multiple physical laptops connected to the same Wi-Fi router or campus switch:

```bash
# On Laptop A (e.g. 192.168.1.101)
python3 main.py --port 8000

# On Laptop B (e.g. 192.168.1.102)
python3 main.py --port 8000

# On Laptop C (e.g. 192.168.1.103)
python3 main.py --port 8000
```

1. **Automatic Discovery:** The nodes will broadcast on UDP port 9999 and appear in each other's dashboards within 3 seconds.
2. **Firewall / Campus Restrictions:** If your campus Wi-Fi blocks UDP broadcast packets, use the manual peer fallback directly in the Web UI or via curl:
   ```bash
   curl -X POST http://192.168.1.101:8000/api/peers/add -H "Content-Type: application/json" -d '{"ip": "192.168.1.102", "port": 8000}'
   ```

---

## 🎓 5-Minute College Viva Demo Script

Follow this step-by-step walkthrough to wow your evaluator in under 5 minutes:

### Act 1: Cooperative 10 MB Chunk Pooling (Aggregation in Action)
1. Launch the cluster: `python3 demo_cluster.py`.
2. Open Node 1's dashboard at `http://127.0.0.1:8001`.
3. In the **Cooperative Download Coordinator** panel, click the blue **`[60 MB Pooled Demo]`** preset button.
4. Click **Start Cooperative Download**.
5. **What to show the evaluator:**
   - The interactive 10 MB chunk grid illuminates in real-time with color-coded worker IDs (`self-0`, `helper-node2`, `helper-node3`).
   - The dual-curve telemetry chart plots **My Local WAN Speed** (Blue) alongside **LAN Pooled Boost Speed** (Emerald).
   - The aggregate throughput is significantly higher than a single WAN stream.

### Act 2: Good Samaritan Boost Notification (Node 2)
1. On Node 1's dashboard, click the **Broadcast Boost** button.
2. Click the clickable peer link for Node 2 (`127.0.0.1:8002 ↗`) to open Node 2's dashboard in a new tab.
3. **What to show the evaluator:**
   - An interactive dark-carbon **Good Samaritan Boost Toast** appears on Node 2 with the prompt: *"Peer Node 1 is downloading a large file. Boost sharing bandwidth to 80%?"*.
   - Click **Boost (80%)** — Node 2's badge instantly updates to `BOOST 80%`.

### Act 3: Game Focus Mode Popup Suppression (Node 3)
1. Switch to Node 3's dashboard (`http://127.0.0.1:8003`).
2. **What to show the evaluator:**
   - Point to the header badge displaying `GAME FOCUS 15%`.
   - Point out that **NO toast popup appeared on Node 3**, even though a boost was broadcasted across the entire cluster.
   - Explain **Safeguard #11**: LANPool detects fullscreen games and silences non-essential notifications (`game_mode_silent`) so the student's competitive gaming ping is never interrupted.

### Act 4: Self-Healing Failover (Killing a Helper Mid-Chunk)
1. Start another 60 MB pooled download on Node 1.
2. In a separate terminal, kill Node 2's process while chunks are actively downloading:
   ```bash
   pkill -f "main.py --port 8002"
   ```
3. **What to show the evaluator:**
   - Watch the chunk grid on Node 1. The chunk that was assigned to Node 2 changes from `downloading` to `requeued` with retry count incremented to `1`.
   - Node 1 or Node 3 picks up the orphaned chunk and completes it.
   - The download succeeds with **0 corrupted bytes**, verified by exact SHA-256 match!

### Act 5: Phase 1 Instant Zero-WAN LAN Cache Hit
1. On Node 1, click **`[60 MB Pooled Demo]`** and click **Start Cooperative Download** again.
2. **What to show the evaluator:**
   - The transfer completes in **0.02 seconds**!
   - Status reports: `STATUS: COMPLETED (local_cache)`.
   - `WAN Bytes: 0 B` — upstream server was not contacted for a single byte.

---

## 🧪 Comprehensive Verification Suite (All 7 Gates)

The codebase includes automated, assert-based test gates covering the implemented feature set. The Stage 5/6 gates validate QoS state transitions, not enforced throughput; see [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

```bash
# Run the complete test suite and generate PROJECT_STATE.md
python3 scripts/export_state.py
```

### Individual Verification Gates:
- `python3 verify_stage1.py 8000`: Single-node 10 MB micro-chunk slicer, disk writer, SHA validation.
- `verify_stage2.py 8000`: 10 GB True-LRU cache, traversal attacks (`..%2F`), eviction, F1–F5 deduplication.
- `python3 verify_stage3.py`: UDP broadcast discovery, 15s peer reap, manual fallback, `SO_REUSEPORT`.
- `python3 verify_stage3_5.py`: Security audit remediation (10 checks: SSRF, ETag pinning, 409/429 concurrency).
- `python3 verify_stage4.py`: Cooperative pooling, mid-chunk SIGKILL self-healing, Phase 1 peer & local cache.
- `python3 verify_stage5.py`: QoS Watchdog, Game Mode process scanner, Good Samaritan Boost protocol.
- `python3 verify_stage6.py`: 3-Node Demo Cluster, throttled origin, live pooled transfer, clean teardown.

---

## 👥 Contributors & Academic Context

- **Institution:** Computer Networks Laboratory, Department of Computer Science & Engineering
- **Project Topic:** Cooperative Peer-to-Peer Bandwidth Aggregation & Decentralized Ring-Buffer Cache Daemon
- **Architecture Lead & Builder Engine:** Antigravity Builder / Lead Engineer
