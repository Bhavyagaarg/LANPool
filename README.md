# LANPool

Cooperative downloads and a 10 GiB content-addressed cache for trusted LAN peers.
Python 3.12+; validated locally on Windows with Python 3.12 and 3.14.

LANPool downloads files submitted through its API/dashboard. It does not intercept
Steam, other launchers, or arbitrary laptop traffic. It runs in a terminal rather
than installing a Windows service. See [FIXES.md](FIXES.md) for the audit remediation
and [SECURITY.md](SECURITY.md) before exposing a node to a network. The separate
25-item Ponytail review is resolved in [PONYTAIL_STATUS.md](PONYTAIL_STATUS.md).
Existing rights remain reserved; see [LICENSE](LICENSE).

## Install and run

```powershell
git clone https://github.com/Bhavyagaarg/LANPool.git
cd LANPool
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe demo_cluster.py
```

Dependencies are pinned in `requirements.lock`; `requirements.txt` includes it.
On macOS/Linux use `python3` and `.venv/bin/python` for the equivalent commands.
Windows users with an existing environment can double-click `Start-Demo.cmd`.

The demo opens http://127.0.0.1:8001 with helpers on 8002/8003 and an origin on
8090. It creates an ephemeral peer group key, binds nodes to localhost, explicitly
allows the local demo origin, checks ports, and writes per-node logs under
`demo_runtime/node_<port>/node.log`. Press Ctrl+C to stop. `--no-browser` suppresses
opening a browser. `--headless-check` runs the automated demonstration and exits.
`--cleanup` removes only the demo's runtime folder on shutdown.
Headless checks use a separate temporary runtime and preserve interactive demo data.

For one node: `.\.venv\Scripts\python.exe main.py` (http://127.0.0.1:8000),
or `Start-Node.cmd`. The default origin policy rejects loopback/private addresses.
Enable `LANPOOL_ALLOW_LOOPBACK=1` only for a trusted local origin, and
`LANPOOL_ALLOW_PRIVATE=1` only if you intend to allow internal-network origins.

## Architecture and download behavior

`main.py` owns the FastAPI lifecycle, bounded jobs/helpers, authentication, job
history, and dashboard. `core/downloader.py` coordinates:

1. An upstream range probe to establish size and a strong ETag.
2. A verified local-cache copy (Phase 1a).
3. An authenticated peer-cache stream (Phase 1b).
4. Up to four total local/helper workers fetching validated 10 MiB ranges
   (Phase 2), with bounded retries and helper failover.

Every range must match the requested start/end/total and identity encoding.
Network bodies are bounded while streaming. A single writer owns the output;
disk operations/hashing run off the event loop and finish before cancellation
closes their resources. The final SHA-256 is computed before publishing.

A trusted publisher SHA-256 is required to use peer content by default. Without
it, a job downloads directly using its own origin workers. Group authentication
alone does not prove a helper's honesty. `LANPOOL_TRUST_GROUP_CONTENT=1` explicitly
allows content without an independent hash from an enrolled group; the controlled
single-PC demo/tests enable it. Do not enable it for an untrusted group.
Multi-chunk downloads without a strong ETag also require this expected hash. Weak/missing ETags never authorize URL cache reuse. Existing
legacy cache validators are invalidated once; content remains accessible by hash.

Example request:

```json
{"url":"https://example.org/file.iso","filename":"file.iso","expected_sha256":"<64 hex characters from a trusted publisher>"}
```

Completed files consistently remain in the node's `downloads/` folder, regardless
of solo, pooled, or cache-hit source. An independent atomic copy is stored in the
cache when quota/free space permit; downloads remain intact if caching is skipped.
The cache copy is also downloadable through the dashboard. This uses additional
disk space; the 10 GiB limit applies to the cache, not the retained user outputs.
Cache copies/streams verify hashes, read leases prevent eviction/renaming during
use, URL aliases survive content deduplication, and LRU reads persist access times in debounced batches (at most two seconds
between background flushes, plus a final flush on clean shutdown).
Quota is enforced on rebuild and registration; an active lease can cause new
caching to be skipped until capacity is available.

Online cache hits still perform the origin probe. Payload counters do not include
HTTP headers or every wire byte. For offline access, provide `offline:true` plus
`expected_sha256`; this only uses a verified local cached hash and makes no origin
request. The URL remains request metadata in this mode.

## Peers and secure LAN deployment

Use a different admin token on each node and a high-entropy shared peer group key.
Generate values with `python -c "import secrets; print(secrets.token_hex(32))"`.
Set these environment variables before starting each node:

```powershell
$env:LANPOOL_API_TOKEN = '<unique administrative token for this node>'
$env:LANPOOL_PEER_SECRET = '<same random peer group key on enrolled nodes>'
$env:LANPOOL_CA_FILE = 'C:\certificates\lan-ca.pem'
.\.venv\Scripts\python.exe main.py --host 0.0.0.0 --tls-certfile C:\certificates\node.pem --tls-keyfile C:\certificates\node-key.pem
```

Certificates must validate for the advertised IP. TLS certificate verification is
never disabled. UDP beacons include signed transport metadata; peer API messages
are signed with timestamps/nonces and content hashes. The admin token is never
sent to peers. Nodes with different group keys cannot pool work. Without a group
key, discovered entries are unpaired and cannot receive jobs.

LAN binding requires both credentials and TLS. A deliberately trusted VPN/network
can opt into HTTP with `LANPOOL_ALLOW_INSECURE_LAN=1`; HMAC does not hide content.
Never expose the service directly to the Internet. Firewall configuration remains
the user's responsibility; setup does not alter Windows security settings.

For blocked UDP, add an IPv4 peer with the dashboard's HTTP/HTTPS selector or
`POST /api/peers/add {"ip":"192.168.1.102","port":8000,"scheme":"https"}`.
A nonce-bound health proof establishes group membership. Manual endpoints are
preserved and periodically refreshed for availability/QoS; offline peers stop
receiving jobs. An unpaired entry is displayed as such.

## QoS, boost, and telemetry

Throttling defaults on. Each node has one aggregate sharing budget, default
20 MiB/s baseline (`LANPOOL_MAX_HELPER_KBPS=20480`). Sharing percentage scales
that capacity; helper origin reads, helper sends, and cache streams share the
same budget. Charging both helper receive/send is intentionally conservative.
Zero share rejects helper/cache-serving work. Owner-initiated downloads are not
limited by the sharing slider; this is an application budget, not OS/router QoS.

The watchdog scans configured process names every five seconds. It does not
inspect fullscreen/foreground windows or guarantee game latency. A detected or
simulated game caps the sharing budget at 15% and suppresses boost prompts.
The dashboard exposes the limiter toggle, baseline/budget, and process simulation.

Pooled Phase-2 jobs of at least 20 MiB automatically request boost. Accepting a
request leases 80% sharing without overwriting the baseline. Matching job
completion/failure/cancellation releases it; a 60-second maximum lease handles a
lost requester. A manual dashboard boost also expires after 60 seconds.

The chart reports recent sampled MiB/s, not whole-job averages mislabeled as MB/s.
`wan_bytes` counts successfully assembled requester payload; `origin_received_bytes`
also counts requester retry bodies. `helper_origin_bytes` counts successful helper
payload, not lost helper attempts. `probe_requests` makes freshness traffic explicit.
None is a full network-interface/HTTP-overhead WAN meter.

The dashboard selects among jobs, displays terminal status/errors, and supports
cancel and Retry from beginning. Metadata history survives restart in each node's
`downloads/jobs.json`; interrupted jobs become cancelled. Partial byte-range resume
is deliberately unsupported because it needs a persistent verified chunk manifest.
Authenticated cache downloads use a 30-second, single-use, hash-scoped grant, so
normal browser downloads stream to disk without buffering a multi-GB Blob or
putting the administrative token in a URL.

## Verification and benchmarking

```powershell
.\.venv\Scripts\python.exe verify_regressions.py
.\.venv\Scripts\python.exe scripts/export_state.py
```

The first runs adversarial security/integrity/QoS/cancellation/API tests; the second
runs all seven stage gates in fresh temporary cache/download directories and
writes the ignored `PROJECT_STATE.md`. Stage 5 measures real 10%/Game Mode helper
throughput; Stage 6 observes automatic boost acceptance and completion release.
Stage 1/2 require the suite's isolated fixture server and refuse unsafe direct CLI
use. Config imports do not create storage directories. The test-file HTTP endpoint
is disabled by default; demo/gates explicitly enable `LANPOOL_TEST_FILES=1`. Enabled
fixtures stream 64 KiB blocks with bounded concurrency, and HEAD allocates no file.
Stop other LANPool demos first: discovery tests assume their own isolated cluster.
CI runs both suites on Windows/Linux with Python 3.12 and 3.14.

With a demo already running, compare equally parallel fresh jobs:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --url http://127.0.0.1:8090/files/game-update-60mb.pak --repeats 3
```

Both modes use the four-worker ceiling and bypass both cache phases. Results are
written to `benchmark-results.json`. Helpers cannot increase a shared saturated
router uplink's capacity. Benefits depend on per-station/per-stream limits,
independent links, or cache reuse; a single-PC demo is not a physical WAN benchmark.
