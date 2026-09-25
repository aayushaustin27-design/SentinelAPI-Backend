@echo off
echo ========================================================
echo Starting Standalone Vulnerable Sandbox API (Port 8001)
echo ========================================================

set "PATH=%~dp0..\tools\python311;%~dp0..\tools\python311\Scripts;%PATH%"

cd /d "%~dp0"
echo Starting Vulnerable Target API at http://127.0.0.1:8001 ...
echo Sandbox Docs: http://127.0.0.1:8001/docs
python -m uvicorn app.sandbox.target_api:sandbox_app --host 127.0.0.1 --port 8001 --reload
pause
