# Validation for the audit-fix branch

Local platform: Windows, 1 November 2026. Application dependencies are recorded
in `requirements.lock`. The branch's review resolutions are listed in `FIXES.md`.

| Verification | Result |
|---|---|
| Adversarial regression suite, Python 3.14 | 28 passed |
| Adversarial regression suite, Python 3.12 | 28 passed |
| Installed dependency consistency | `pip check` passed |
| Legacy stage gates 1, 2, 3, 3.5, 4, 5, 6 | All seven passed |
| Nested CLI demo startup and teardown | Passed |
| Headless checks preserve existing interactive demo storage | Passed |
| Live 60 MiB pooled transfer and SHA-256 verification | Passed; 40 MiB requester + 20 MiB helpers |
| Repeat local-cache copy | Passed |
| Real HTTP 10 MiB helper at configured 10% share | 13.065 s; above the 5 s minimum ceiling check |
| Real TLS connection and manual group enrollment | Passed with trusted certificate; rejected without trust |
| Browser review in Microsoft Edge | Cache entries, paired peers, job controls and MiB/s telemetry rendered |

Regression coverage includes wrong offsets/totals, oversized responses, missing/
weak validators, cache tampering, expected final hashes, offline access without
origin requests, admin-token isolation, request signatures/replay, malformed UDP,
DNS pinning and private-origin policy, helper concurrency, measured aggregate QoS,
boost lifecycle, persistent history/retry, Windows cancellation/file cleanup,
server cancellation scopes, disconnect-before-first-body cleanup for cache/helper
streams, durable LRU/aliases, startup quota, read leases, unique dashboard fields,
scoped single-use browser grants, request body limits, and rebound Host rejection.

The live QoS measurement charges both helper origin reads and sends, so a helper's
end-to-end rate can be lower than its configured shared-byte budget. The target
is a ceiling rather than a throughput guarantee. A single-PC equal-concurrency
benchmark also showed pooling can be slower under sharing limits; the benchmark
does not establish additional physical WAN capacity.

Local evidence is intentionally ignored by Git: `PROJECT_STATE.md`,
`verification-fixes.log`, `verification-stage6-final.log`,
`regression-results-py312.log`, `regression-results-py314.log`,
`LOCAL_SMOKE_RESULTS.json`, and `benchmark-results.json`.

The GitHub Actions workflow configures Windows/Linux and Python 3.12/3.14, but its
remote runs require publishing the branch. Linux, physical multi-laptop discovery,
actual independent WAN links, multi-gigabyte sustained load, and real-game latency
were not tested locally. Process detection was exercised with a controlled real
process; it is not claimed to detect fullscreen windows.

Reproduce with `python verify_regressions.py` and
`python scripts/export_state.py` after stopping unrelated LANPool demos.
