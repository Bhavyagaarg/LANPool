# Remediation of the 1 November 2026 review

This branch addresses the 30 numbered findings in the initial local review.
Architectural limits are stated explicitly rather than represented as performance
or security guarantees. The historical local report is not a current bug list.

| # | Resolution | Evidence / implementation |
|---|---|---|
| 1 | Separate admin/peer credentials; authenticated discovery, fresh manual proof, replay-resistant peer requests, signed content and TLS support | `core/peer_auth.py`, security regressions; LAN TLS required unless explicitly overridden |
| 2 | Exact Content-Range offsets/end/total and identity encoding | Worker shared by solo/helper; wrong-offset regressions |
| 3 | Real aggregate byte pacing, default on, zero-share rejection, UI toggle | Concurrent measured rate test; helper/cache stream pacing |
| 4 | No weak/missing-validator cache reuse; multi-chunk needs strong validator or final trusted hash | Missing/weak ETag regressions; legacy validator migration |
| 5 | Hash-verified leased cache copies/streams | Same-size tampering and offline verification tests |
| 6 | Optional trusted expected SHA-256; authenticated peer content digests | Mismatch rejected before publication |
| 7 | Localhost default, authenticated/TLS LAN mode, explicit private-origin policy, DNS-pinned connections | Policy/pinning and API tests |
| 8 | Four incoming helpers per node with 429 backpressure | Eight concurrent requests: four accepted, four rejected |
| 9 | Bounded streaming for solo/helper payloads and peer metadata/errors | Oversized-origin test stops after two blocks |
| 10 | Dashboard consumes API `items` and actual configured quota | API contract test and browser review |
| 11 | Missing typing import fixed; supported Python baseline documented | Regression suites on Python 3.12/3.14 |
| 12 | Automatic threshold boost before eligible pooled work | Automatic request/release regression |
| 13 | Job-scoped boost plus expiry; baseline retained | Release/expiry tests and completion cleanup |
| 14 | Hash-scoped single-use browser download grants | Protected download succeeds without exposing admin token |
| 15 | Recent MiB/s samples, separate average, explicit requester/helper/probe counters | API/UI unit alignment; counters documented |
| 16 | Explicit expected-hash offline-local mode, online probe disclosed | Offline test forbids origin access |
| 17 | Shared-uplink limits documented; equal-worker cache-bypassing benchmark added | `scripts/benchmark.py`; no claim of extra shared WAN capacity |
| 18 | All ports checked/reserved before launch; dynamic nondefault ports; child logs and exit checks | Stage 6 including nested CLI startup |
| 19 | Awaited writer/worker/wait-task cancellation and disk-resource cleanup; QoS shutdown awaited | Cancellation race regression, including Windows open-file case |
| 20 | Disk/hash/cache operations off event loop; threaded I/O awaited before close | Downloader I/O helpers and cancellation tests |
| 21 | Persistent URL/validator alias sets per content hash | Deduplication/restart regression |
| 22 | Startup quota enforcement; failed deletion/leased entries retain accounting | Small-quota and active-lease tests |
| 23 | Read access persisted; flush on shutdown | Restart preserves latest access time |
| 24 | Verified read leases prevent rename/eviction | Active reader tests; cache registration skips pinned quota |
| 25 | Strict share/type/finite timestamp checks, HMAC beacons | Malformed/unsigned datagram tests |
| 26 | Manual health/QoS leases refresh without UDP; offline entries excluded from work | Registry refresh path; preserved manual address |
| 27 | Job selector, real status/error, cancel, persistent metadata and fresh retry | History/retry API test; restart marks interrupted work cancelled |
| 28 | Process-name detection described accurately; real-process scanner test | No fullscreen/latency guarantee advertised |
| 29 | Adversarial regression suite, position-dependent payloads, CI matrix and browser review | `tests/test_regressions.py`, stage gates, CI workflow |
| 30 | Canonical README/security/limitations, correct clone URL, pinned lock, current agent instructions | Generated/private artifacts excluded |

Partial byte-range resume is not advertised: Retry deliberately revalidates and
starts from the beginning. OS/router traffic shaping, physical multi-WAN capacity,
and guaranteed game latency are outside the application contract. The watchdog's
sharing budget does not limit downloads explicitly initiated by the machine owner.

Run `python verify_regressions.py` and `python scripts/export_state.py` for current
results. See `VALIDATION.md` for the validation performed for this branch.
