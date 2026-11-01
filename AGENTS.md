# Working on LANPool

- Application code lives in the repository root plus `core/`. `src/handshake.py`
  is historical tooling, not a second application.
- Prefer Serena symbol tools if available. When unavailable, native file/code
  tools are supported; mention the fallback in the work report.
- Keep the admin token local to its node; never forward it to peers. Preserve
  signed peer enrollment/requests/content, TLS verification, origin IP pinning,
  bounded bodies/concurrency, exact range validation, and expected-hash checks.
- Changes to worker lifecycle or disk I/O must preserve awaited cancellation and
  Windows file-handle cleanup. Cache streams/copies must hold read leases.
- Validate with `python verify_regressions.py` and `python scripts/export_state.py`.
  Stop unrelated LANPool demos first; network tests assume an isolated cluster.
- Update README, SECURITY, FIXES, or KNOWN_ISSUES when the supported contract
  changes. Historical implementation-plan stages are not approval gates.
- No external dispatcher or absent `.agents` board is required. Do not commit
  runtime data, credentials, virtual environments, local logs, or state snapshots.
