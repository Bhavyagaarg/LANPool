"""Run the adversarial suite with a portable combined-output log and exit status."""
import os
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    env = {**os.environ, "PYTHONUTF8": "1"}
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    (root / "regression-results.log").write_text(result.stdout, encoding="utf-8")
    (root / f"regression-results-py{sys.version_info.major}{sys.version_info.minor}.log").write_text(result.stdout, encoding="utf-8")
    print(result.stdout)
    sys.exit(result.returncode)
