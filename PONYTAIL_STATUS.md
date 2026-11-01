# Response to PONYTAIL_REVIEW.md

Reviewed on 1 November 2026 against `fix/security-integrity-qos`. The supplied
Ponytail report describes original commit `a24979f`; this response uses its own
25 finding numbers, which differ from the 30-item initial local review.

**Not every Ponytail finding was resolved in the first fix commit.** The follow-up
fixes below address the remaining gaps, and strengthen tests for earlier fixes.
All seven stage gates now pass. All **43 regression tests pass on both Python
3.12 and 3.14** on this Windows laptop. The original review file was left intact.

| Ponytail # | Current resolution | Evidence / limits |
|---|---|---|
| 1 | Real aggregate byte pacing, enabled by default, with UI toggle and zero-share rejection | Stage 5 now times actual 10 MiB HTTP transfers: 11.729 s at 10% (minimum 5 s), 8.883 s in Game Mode 15% (minimum 3.333 s). Both receive/send consume the budget, so rates may be lower than the ceiling. |
| 2 | Automatic threshold notification; accepting creates a job lease without changing baseline; completion releases it; expiry handles lost requesters | Stage 6 observes the notification during a real pooled job, accepts it through HTTP, and verifies release/baseline restoration. Regression tests cover expiry and cancellation cleanup. |
| 3 | Peer IDs have a restricted short charset; unsafe requested filenames are rejected; dashboard escapes legacy filenames and peer text | `test_html_node_ids_are_rejected_even_with_group_trust`, `test_xss_filename_rejected_before_any_download_starts`; template escaping inspected. No new browser automation was performed for this follow-up. |
| 4 | Administrative token is never forwarded; distinct peer signatures authenticate requests/content | `test_even_authenticated_peer_requests_never_include_admin_token` captures actual constructed headers, including a peer signature and no admin-token header. |
| 5 | Public-origin policy by default; private/loopback origins need explicit opt-in; connection uses validated IP; localhost Host/origin checks; secure LAN binding | Policy, pinning, rebound Host, TLS, and authentication regressions. Tests/demo opt into their local fixture origin. |
| 6 | Missing/weak ETags cannot authorize URL cache reuse | Mutable no-ETag origin and weak-validator tests. Multi-chunk downloads also require a strong validator or a trusted final hash. |
| 7 | LRU reads mark metadata dirty; writes are debounced; daemon flushes every two seconds and on clean shutdown | 200 lookups do not cause 200 writes; flush/restart retains the latest access. A forced crash can lose the most recent unflushed access timestamps. |
| 8 | Every cache copy/stream takes a verified read lease; local copies also hash the destination | Same-size, restored-mtime corruption is rejected/repaired. Fast boot metadata is not treated as proof that served bytes are valid. |
| 9 | Completed outputs consistently stay in `downloads/`; cache receives an independent atomic copy | Editing the retained download does not change the cache. Cache-owned import files may be canonicalized internally. Cache/download directories cannot be identical. Copies consume extra disk space; caching can be skipped without deleting the completed output. |
| 10 | UI reads `data.items` and actual configured quota | Existing API/DOM contract tests; the earlier browser check displayed populated cache rows. |
| 11 | Normal browser downloads use short-lived, single-use, hash-scoped grants obtained with the admin header | Protected cache/grant test succeeds and reuse is denied. Large files stream to disk rather than a whole-file Blob. |
| 12 | Datagram types, 0–100 shares, boolean QoS flags, finite timestamps, signature format, and peer ID charset are checked | Malformed, unsigned, NaN, bad-share and HTML-ID tests; bad input does not escape into the UI/parser. |
| 13 | Both configured names and process names normalize a trailing `.exe` | Tests cover `cs2`/`CS2.exe`, `dota2`/`DOTA2.EXE`, and reject launcher-prefix false positives. Actual native Linux games were not run on this Windows laptop. |
| 14 | Test-file API disabled by default; enabled fixture streams use random-access 64 KiB blocks and four stream slots; HEAD only returns metadata | A 100 MiB generator stays below 3 MiB of traced allocations, HEAD never invokes payload generation, and a 21-byte range across a block boundary returns correct bytes. This is generator memory, not total process RSS. |
| 15 | Entire exported suite uses one fresh owned temporary storage root and restores environment afterward; config import creates no storage directories | Exporter ownership/cleanup/environment tests; CLI Stage 1/2 refuse use outside the isolated suite. The exporter no longer unlinks real `downloads/*.bin`/`.part`. |
| 16 | Stage 5/6 themselves now exercise real throughput and automatic job-scoped boost | Measured Stage 5 checks and Stage 6 live HTTP acceptance/release, in addition to independent regression tests. A labels-only limiter cannot pass these gates. |
| 17 | Production peer content requires a trusted expected SHA-256 by default; otherwise the job uses its own origin workers | A malicious helper test returns forged bytes with a valid group signature and matching self-attested digest: final publication/cache registration are rejected. Controlled demo/tests explicitly set `LANPOOL_TRUST_GROUP_CONTENT=1`. Enabling that override deliberately trusts group members and does not prove peer honesty. |
| 18 | A different-ID UDP collision cannot replace a manually enrolled endpoint | Direct attempted takeover is rejected even if the beacon has group trust. A restart can update identity only after a fresh authenticated HTTP health proof from the enrolled endpoint. |
| 19 | Verification nodes use individually allocated distinct ephemeral TCP ports | Shared allocator holds all requested sockets until selection completes; demo validates/reserves its complete port set and reports startup errors. No claim of an atomic cross-process handoff. |
| 20 | Lifespan awaits QoS shutdown and all owned task/resource cleanup | Shutdown, cancellation-scope, Windows file-handle, and disconnect-before-first-byte regressions. |
| 21 | `PROJECT_STAGE = 6` and `APP_VERSION` feed health, fallback and dashboard metadata | Health test asserts the shared constant; UI renders version/stage from health. |
| 22 | Canonical README/security/limits updated; old plan explicitly historical; no absent board required | Current routes, hashing trust, offline behavior, QoS limits, storage policy, and fixture configuration documented. No fixed cache-hit time promised. |
| 23 | LICENSE notice added with **existing rights reserved**, as requested; Python baseline and agent instructions aligned | No open-source permissions were granted. Supported documented baseline is Python 3.12+; local tests ran on 3.12 and 3.14. |
| 24 | Interactive runtime remains intentionally persistent, and shutdown prints its resolved location and cleanup option | Demo code logs the preserved path. Headless checks use owned temporary storage and verify existing interactive data survives. |
| 25 | Solo/helper downloads use the same range/ETag validation; weak comparisons use `normalize_etag` | Equivalent weak/strong opaque tags are tested for weak validators. A pinned strong validator still rejects a weakened/changed response. Weak validators never enable URL cache reuse. |

## Reproduction and evidence

```powershell
.\.venv\Scripts\python.exe verify_regressions.py
.\.venv312\Scripts\python.exe verify_regressions.py
.\.venv\Scripts\python.exe scripts\export_state.py
```

The second environment is local to this laptop; elsewhere create an environment
with Python 3.12 first. Logs/snapshots remain local and ignored by Git:

- `regression-results-py312.log`, `regression-results-py314.log` — 43 passing tests each.
- `verification-ponytail.log` — seven passing stage gates.
- `PROJECT_STATE.md` — actual gate output, measured timings, automatic boost evidence,
  isolated fixture paths, and source snapshot.

This resolves the enumerated report findings under the documented settings. It
does not establish absence of every possible bug, actual native-game latency,
multi-laptop firewall behavior, multi-gigabyte soak performance, mobile/browser
compatibility, or physical multi-WAN gains. A trusted publisher hash must come
from an independent trusted source; obtaining it from the same untrusted helper
would defeat the protection. Do not enable the explicit group-content trust
override for a group whose members might substitute content.
