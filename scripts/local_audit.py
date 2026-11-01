"""Run the maintained regression checks for the initial local audit."""
import runpy
from pathlib import Path
runpy.run_path(str(Path(__file__).resolve().parents[1] / "verify_regressions.py"), run_name="__main__")
