@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
"%~dp0.venv\Scripts\python.exe" demo_cluster.py %*
if errorlevel 1 pause
