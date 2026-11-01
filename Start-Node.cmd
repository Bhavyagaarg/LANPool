@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
echo LANPool dashboard: http://127.0.0.1:8000
echo Press Ctrl+C to stop.
"%~dp0.venv\Scripts\python.exe" main.py --host 127.0.0.1 %*
if errorlevel 1 pause
