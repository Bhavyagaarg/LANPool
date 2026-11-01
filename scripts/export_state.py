#!/usr/bin/env python3
"""
LANPool Project State Exporter (scripts/export_state.py)
Generates PROJECT_STATE.md at the project root containing:
1. Task board summary: STATUS + CURRENT_DIRECTION from .agents/board.md
2. Directory tree of project root (excluding caches, binaries, downloads, venv, git) with file sizes
3. Real execution outputs of verification gates (Stages 1, 2, 3, 3.5, 4, 5, and 6)
4. Complete source code of all project .py files
"""

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BOARD_FILE = PROJECT_ROOT / ".agents" / "board.md"
AUDIT_FILE = PROJECT_ROOT / ".agents" / "code_audit.md"
OUTPUT_FILE = PROJECT_ROOT / "PROJECT_STATE.md"

EXCLUDED_DIR_NAMES = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    ".serena",
    ".taskmaster",
    "node_modules",
    "graphify-out",
}


def get_free_port() -> int:
    """Finds a free ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def extract_board_summary() -> str:
    """Extracts STATUS and CURRENT_DIRECTION from .agents/board.md."""
    if not BOARD_FILE.exists():
        return "No .agents/board.md file found."
    content = BOARD_FILE.read_text(encoding="utf-8")
    lines = content.splitlines()
    summary_lines: List[str] = []
    capturing = False
    for line in lines:
        if line.startswith("STATUS:"):
            capturing = True
        elif line.startswith("REVIEW_NOTES:") or line.startswith("BUILDER_FEEDBACK:"):
            break
        if capturing:
            summary_lines.append(line)
    return "\n".join(summary_lines).strip()


def should_exclude_file_from_tree(rel_path: Path) -> bool:
    """Filters out binary payloads, downloads, part files, and bytecode."""
    parts = rel_path.parts
    if len(parts) > 1 and parts[0] == "LANPool_Cache" and rel_path.suffix == ".bin":
        return True
    if len(parts) > 1 and parts[0] == "downloads" and len(parts) > 1:
        return True
    if rel_path.suffix in (".part", ".pyc"):
        return True
    return False


def build_directory_tree(root: Path) -> str:
    """Constructs an ASCII tree of the project structure showing file sizes."""
    lines = [f"{root.name}/"]

    def _walk(curr: Path, prefix: str):
        entries = []
        try:
            items = sorted(curr.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except Exception:
            return

        for item in items:
            if item.is_dir():
                if item.name in EXCLUDED_DIR_NAMES:
                    continue
                entries.append(item)
            else:
                rel = item.relative_to(root)
                if should_exclude_file_from_tree(rel):
                    continue
                entries.append(item)

        for i, entry in enumerate(entries):
            is_last = (i == len(entries) - 1)
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "
            if entry.is_dir():
                lines.append(f"{prefix}{connector}{entry.name}/")
                _walk(entry, prefix + extension)
            else:
                size = entry.stat().st_size
                lines.append(f"{prefix}{connector}{entry.name} ({size:,} B)")

    _walk(root, "")
    return "\n".join(lines)


def wait_for_server(port: int, max_retries: int = 40, delay: float = 0.25) -> bool:
    """Polls /api/health until server responds with HTTP 200."""
    url = f"http://127.0.0.1:{port}/api/health"
    for _ in range(max_retries):
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def run_verification_gates(port: int) -> Tuple[bool, str, bool, str]:
    """
    Boots main.py on ephemeral port, runs verify_stage1.py and verify_stage2.py,
    and terminates the server in a finally block.
    """
    server_cmd = [sys.executable, "main.py", "--port", str(port)]
    server_proc = subprocess.Popen(
        server_cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    stage1_output = ""
    stage2_output = ""
    stage1_ok = False
    stage2_ok = False

    try:
        online = wait_for_server(port)
        if not online:
            err_msg = "Server failed to start or /api/health did not respond within timeout."
            return False, err_msg, False, err_msg

        # Run verify_stage1.py
        p1 = subprocess.run(
            [sys.executable, "verify_stage1.py", str(port)],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stage1_ok = (p1.returncode == 0)
        stage1_output = p1.stdout.strip()

        # Run verify_stage2.py
        p2 = subprocess.run(
            [sys.executable, "verify_stage2.py", str(port)],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stage2_ok = (p2.returncode == 0)
        stage2_output = p2.stdout.strip()

    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()
        for f in (PROJECT_ROOT / "downloads").glob("*.bin"):
            f.unlink(missing_ok=True)
        for f in (PROJECT_ROOT / "downloads").glob("*.part"):
            f.unlink(missing_ok=True)

    return stage1_ok, stage1_output, stage2_ok, stage2_output


def run_stage3_verification_gate() -> Tuple[bool, str]:
    """Runs verify_stage3.py which manages its own ephemeral nodes on 8091 and 8092."""
    p3 = subprocess.run(
        [sys.executable, "verify_stage3.py"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (p3.returncode == 0), p3.stdout.strip()


def run_stage3_5_verification_gate() -> Tuple[bool, str]:
    """Runs verify_stage3_5.py which tests all 20 audit remediation items."""
    p35 = subprocess.run(
        [sys.executable, "verify_stage3_5.py"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (p35.returncode == 0), p35.stdout.strip()


def run_stage4_verification_gate() -> Tuple[bool, str]:
    """Runs verify_stage4.py testing cooperative pooling, cache hits, and failover."""
    p4 = subprocess.run(
        [sys.executable, "verify_stage4.py"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (p4.returncode == 0), p4.stdout.strip()


def run_stage5_verification_gate() -> Tuple[bool, str]:
    """Runs verify_stage5.py testing QoS watchdog, boost protocol, and Web UI."""
    p5 = subprocess.run(
        [sys.executable, "verify_stage5.py"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (p5.returncode == 0), p5.stdout.strip()


def run_stage6_verification_gate() -> Tuple[bool, str]:
    """Runs verify_stage6.py testing 3-node demo cluster, throttled origin, and viva suite."""
    p6 = subprocess.run(
        [sys.executable, "verify_stage6.py"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (p6.returncode == 0), p6.stdout.strip()


def collect_python_sources(root: Path) -> str:
    """Collects complete source of all project .py files in fenced blocks."""
    py_files = []
    for p in root.rglob("*.py"):
        rel = p.relative_to(root)
        parts = rel.parts
        if any(part in EXCLUDED_DIR_NAMES for part in parts):
            continue
        py_files.append((str(rel), p))

    py_files.sort(key=lambda t: t[0])

    sections = []
    for rel_str, p in py_files:
        try:
            content = p.read_text(encoding="utf-8")
        except Exception as e:
            content = f"# Error reading file {rel_str}: {e}"
        sections.append(f"### `{rel_str}`\n```python\n{content}\n```\n")

    return "\n".join(sections)


def export_project_state() -> int:
    """Runs verification gates and exports complete project state to PROJECT_STATE.md."""
    print("Exporting project state to PROJECT_STATE.md...")
    port = get_free_port()
    print(f"Ephemeral verification port allocated: {port}")

    # 1. Task Board Summary
    board_summary = extract_board_summary()

    # 2. Directory Tree
    dir_tree = build_directory_tree(PROJECT_ROOT)

    # 3. Verification Gates Output
    print(f"Executing verification gates on port {port}...")
    s1_ok, s1_out, s2_ok, s2_out = run_verification_gates(port)
    print(f"Stage 1 Gate: {'PASSED' if s1_ok else 'FAILED'}")
    print(f"Stage 2 Gate: {'PASSED' if s2_ok else 'FAILED'}")

    print("Executing Stage 3 verification gate (8091/8092)...")
    s3_ok, s3_out = run_stage3_verification_gate()
    print(f"Stage 3 Gate: {'PASSED' if s3_ok else 'FAILED'}")

    print("Executing Stage 3.5 verification gate...")
    s35_ok, s35_out = run_stage3_5_verification_gate()
    print(f"Stage 3.5 Gate: {'PASSED' if s35_ok else 'FAILED'}")

    print("Executing Stage 4 verification gate...")
    s4_ok, s4_out = run_stage4_verification_gate()
    print(f"Stage 4 Gate: {'PASSED' if s4_ok else 'FAILED'}")

    print("Executing Stage 5 verification gate...")
    s5_ok, s5_out = run_stage5_verification_gate()
    print(f"Stage 5 Gate: {'PASSED' if s5_ok else 'FAILED'}")

    print("Executing Stage 6 verification gate...")
    s6_ok, s6_out = run_stage6_verification_gate()
    print(f"Stage 6 Gate: {'PASSED' if s6_ok else 'FAILED'}")

    # 4. Code Audit (written by the Master; optional)
    audit = AUDIT_FILE.read_text(encoding="utf-8").strip() if AUDIT_FILE.exists() else "No code audit recorded."

    # 5. Source Files
    py_sources = collect_python_sources(PROJECT_ROOT)

    overall_status = "PASSED" if (s1_ok and s2_ok and s3_ok and s35_ok and s4_ok and s5_ok and s6_ok) else "FAILED"

    # Assemble Markdown Document
    md_content = f"""# LANPool Project State Snapshot
Overall Verification Status: **{overall_status}**

---
## 1. Task Board Summary (.agents/board.md)
```markdown
{board_summary}
```

---
## 2. Project Directory Tree
```
{dir_tree}
```

---
## 3. Latest Verification Outputs

### Stage 1 Verification Gate ({'PASSED' if s1_ok else 'FAILED'})
```
{s1_out}
```

### Stage 2 Verification Gate ({'PASSED' if s2_ok else 'FAILED'})
```
{s2_out}
```

### Stage 3 Verification Gate ({'PASSED' if s3_ok else 'FAILED'})
```
{s3_out}
```

### Stage 3.5 Verification Gate ({'PASSED' if s35_ok else 'FAILED'})
```
{s35_out}
```

### Stage 4 Verification Gate ({'PASSED' if s4_ok else 'FAILED'})
```
{s4_out}
```

### Stage 5 Verification Gate ({'PASSED' if s5_ok else 'FAILED'})
```
{s5_out}
```

### Stage 6 Verification Gate ({'PASSED' if s6_ok else 'FAILED'})
```
{s6_out}
```

---
## 4. Code Audit (Ponytail)

{audit}

---
## 5. Complete Project Python Source Code

{py_sources}
"""

    OUTPUT_FILE.write_text(md_content, encoding="utf-8")
    print(f"Successfully generated {OUTPUT_FILE} ({len(md_content):,} bytes).")

    return 0 if (s1_ok and s2_ok and s3_ok and s35_ok and s4_ok and s5_ok and s6_ok) else 1


if __name__ == "__main__":
    sys.exit(export_project_state())
