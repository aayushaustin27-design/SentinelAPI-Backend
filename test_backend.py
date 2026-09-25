import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
import httpx
from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    client = TestClient(app)
    
    print("[TEST 1] Healthcheck...")
    res = client.get("/api/v1/health")
    assert res.status_code == 200, f"Healthcheck failed: {res.text}"
    print(f"  -> OK: {res.json()}")

    print("[TEST 2] OpenAPI Spec Parsing (JSON)...")
    sample_spec = client.get("/api/v1/sandbox/sample-spec").json()
    import json
    res = client.post("/api/v1/spec/parse", json={"specContent": json.dumps(sample_spec)})
    assert res.status_code == 200, f"Parse failed: {res.text}"
    data = res.json()
    print(f"  -> OK: Title: '{data['title']}', Endpoints: {data['totalEndpoints']}")

    print("[TEST 3] OpenAPI Spec Parsing (YAML)...")
    yaml_spec = """
openapi: 3.0.0
info:
  title: Test YAML API
  version: 1.0.0
paths:
  /api/v1/users:
    get:
      summary: List users
      responses:
        '200':
          description: OK
"""
    res = client.post("/api/v1/spec/parse", json={"specContent": yaml_spec})
    assert res.status_code == 200, f"YAML parse failed: {res.text}"
    data = res.json()
    print(f"  -> OK: Title: '{data['title']}', Endpoints: {data['totalEndpoints']}")

    print("[TEST 4] Safety Check - Reject Arbitrary Internet Target...")
    res = client.post("/api/v1/scan/execute", json={
        "targetUrl": "https://google.com",
        "specContent": json.dumps(sample_spec),
        "isSandboxConfirmed": True
    })
    assert res.status_code == 400, f"Safety check failed to reject google.com: {res.status_code}"
    print(f"  -> OK: Rejected external internet domain with message: '{res.json().get('detail')}'")

    print("[TEST 5] Sandbox Sub-Application Mounted & Live...")
    res = client.get("/sandbox/api/v1/health")
    assert res.status_code == 200, f"Sandbox health failed: {res.text}"
    print(f"  -> OK: Sandbox response: {res.json()}")

    print("\nALL BACKEND AUTOMATED TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
