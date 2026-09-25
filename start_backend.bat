@echo off
echo ========================================================
echo Starting SentinelAPI Backend (FastAPI + Uvicorn)
echo ========================================================

set "PATH=%~dp0..\tools\python311;%~dp0..\tools\python311\Scripts;%PATH%"

cd /d "%~dp0"
echo Starting SentinelAPI server at http://127.0.0.1:8000 ...
echo Interactive Docs: http://127.0.0.1:8000/docs
echo Built-in Sandbox API: http://127.0.0.1:8000/sandbox/docs
python main.py
pause
