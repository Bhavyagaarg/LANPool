"""Stop only the background demo recorded during local setup."""
from pathlib import Path
import psutil

root = Path(__file__).resolve().parents[1]
pid_file = root / "demo-local.pid"
if not pid_file.exists():
    print("No setup demo PID recorded. For a foreground demo, press Ctrl+C in its window.")
    raise SystemExit(0)
try:
    process = psutil.Process(int(pid_file.read_text().strip()))
    command = process.cmdline()
    if Path(process.cwd()).resolve() != root or not any(Path(arg).name == "demo_cluster.py" for arg in command):
        raise SystemExit("PID belongs to another process; leaving it alone.")
    children = process.children(recursive=True)
    for child in children:
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(children, timeout=3)
    for child in alive:
        child.kill()
    psutil.wait_procs(alive, timeout=3)
    process.terminate()
    process.wait(timeout=3)
except psutil.NoSuchProcess:
    pass
pid_file.unlink(missing_ok=True)
print("Background setup demo stopped. Cached downloads were retained.")
