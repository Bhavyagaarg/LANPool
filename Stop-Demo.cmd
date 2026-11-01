@echo off
setlocal
cd /d "%~dp0"
"%~dp0.venv\Scripts\python.exe" scripts\stop_local_demo.py
if errorlevel 1 pause
