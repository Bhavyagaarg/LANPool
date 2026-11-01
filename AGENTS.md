## 0. Mandatory Serena MCP usage (Master & Builder)
- In every session, before inspecting or editing code, call Serena's `activate_project` on the repo root, then use `get_symbols_overview`, `find_symbol`, `find_referencing_symbols`, `replace_symbol_body`, `insert_after_symbol`, and `replace_content`. This keeps the Serena dashboard telemetry live.
- Use native Read/Edit/Bash only when Serena has no tool for the job or the language server is unavailable; say so in the board reply.
- After an approved stage, update Serena memory (`write_memory`): `core`, `conventions`, and the stage memory (e.g. `stage3_5`, `stage6`).
- Application code lives in the repo ROOT plus `core/`; there is no `src/` app. `src/handshake.py` is the Builder handshake, not product code.

## 1. Decommissioned OpenCode CLI Dispatcher (Historical Context)
- The external OpenCode CLI dispatcher (`opencode run --session ...`) has been permanently decommissioned.
- Antigravity serves as Builder & Lead Engineer, executing architecture plans, running verification gates, reporting directly to the User in chat, and recording persistent state on disk.

## 2. Antigravity IDE = BUILDER & LEAD ENGINEER
- Antigravity writes the code, runs local tests, enforces architectural safeguards, and records progress on disk.
- Execution contracts and directions are tracked in `.agents/board.md`.
- All verification gates and state snapshots are updated via `python3 scripts/export_state.py`.
- No external `opencode run` process is called.

## 3. Shared reference: `.agents/capabilities.md`
- Inventory of tools and capabilities.
- Antigravity executes test suites and verification gates locally and maintains clean system state (no daemon leaks, ports released, caches synchronized).

