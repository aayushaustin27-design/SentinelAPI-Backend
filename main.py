import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from app.main import app

if __name__ == "__main__":
    print("========================================================")
    print("Starting SentinelAPI Backend on http://127.0.0.1:8000")
    print("Documentation: http://127.0.0.1:8000/docs")
    print("Vulnerable Sandbox: http://127.0.0.1:8000/sandbox/docs")
    print("========================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
