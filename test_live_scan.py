import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
from app.scanner.engine import ScannerEngine
from app.models.security import ScanRequest

async def test_live_scan():
    engine = ScannerEngine()
    
    # Using local test sandbox
    # Note: in standalone or mounted sandbox, base URL is http://127.0.0.1:8001 or http://127.0.0.1:8000/sandbox
    req = ScanRequest(
        targetUrl="http://127.0.0.1:8000/sandbox",
        specContent="""
openapi: 3.0.3
info:
  title: SentinelAPI Vulnerable Sandbox Test Target
  version: 1.0.0
paths:
  /api/v1/health:
    get:
      summary: Health check
  /api/v1/public/debug:
    get:
      summary: Public debug
  /api/v1/users/{user_id}/profile:
    get:
      summary: User profile (BOLA)
  /api/v1/orders/{order_id}:
    get:
      summary: Orders (Excessive Data Exposure)
  /api/v1/transfers/quick:
    post:
      summary: Quick Transfer (Rate Limit)
""",
        checkAuth=True,
        checkDataExposure=True,
        checkRateLimit=True,
        checkBola=True,
        isSandboxConfirmed=True
    )
    
    print("[SCAN TEST] Initiating Scan against target URL:", req.targetUrl)
    # We can run an in-process TestClient or live check
    from app.main import app
    from fastapi.testclient import TestClient
    client = TestClient(app)
    
    response = client.post("/api/v1/scan/execute", json=req.model_dump())
    print("Response status:", response.status_code)
    data = response.json()
    print("\n=== SCAN SUMMARY ===")
    print(f"Target: {data['summary']['targetName']}")
    print(f"Duration: {data['summary']['duration']}")
    print(f"Score: {data['summary']['securityScore']}%")
    print(f"Findings Count: {len(data['findings'])}")
    print(f"Severity Breakdown: {data['summary']['severityCounts']}")
    
    print("\n=== FINDINGS ===")
    for f in data['findings']:
        print(f"- [{f['severity']}] {f['title']} ({f['endpoint']}) -> {f['vulnerabilityType']}")

if __name__ == "__main__":
    asyncio.run(test_live_scan())
