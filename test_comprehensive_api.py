import sys
import os
import io
import json

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

def run_comprehensive_test_suite():
    print("=" * 60)
    print("RUNNING SENTINELAPI BACKEND COMPREHENSIVE TEST SUITE")
    print("=" * 60)

    client = TestClient(app)

    # -------------------------------------------------------------
    # 1. Test GET /
    # -------------------------------------------------------------
    print("\n[1] Testing GET / ...")
    res = client.get("/")
    assert res.status_code == 200, f"Failed GET /: {res.text}"
    body = res.json()
    assert body["service"] == "SentinelAPI Backend"
    assert "docs" in body
    assert "sandbox_docs" in body
    print("  -> PASSED: Root metadata correctly returned.")

    # -------------------------------------------------------------
    # 2. Test GET /api/v1/health
    # -------------------------------------------------------------
    print("\n[2] Testing GET /api/v1/health ...")
    res = client.get("/api/v1/health")
    assert res.status_code == 200, f"Failed GET /api/v1/health: {res.text}"
    body = res.json()
    assert body["status"] == "healthy"
    assert body["engine"] == "active"
    assert len(body["security_checks"]) >= 4
    print("  -> PASSED: Healthcheck reporting engine active with 4 check modules.")

    # -------------------------------------------------------------
    # 3. Test GET /api/v1/sandbox/sample-spec
    # -------------------------------------------------------------
    print("\n[3] Testing GET /api/v1/sandbox/sample-spec ...")
    res = client.get("/api/v1/sandbox/sample-spec")
    assert res.status_code == 200, f"Failed GET /api/v1/sandbox/sample-spec: {res.text}"
    sample_spec = res.json()
    assert sample_spec["openapi"].startswith("3.")
    assert "paths" in sample_spec
    assert "/api/v1/users/{user_id}/profile" in sample_spec["paths"]
    print(f"  -> PASSED: Sample sandbox spec returned with {len(sample_spec['paths'])} endpoints.")

    # -------------------------------------------------------------
    # 4. Test POST /api/v1/spec/parse (JSON and YAML)
    # -------------------------------------------------------------
    print("\n[4.1] Testing POST /api/v1/spec/parse with JSON string ...")
    res = client.post("/api/v1/spec/parse", json={"specContent": json.dumps(sample_spec)})
    assert res.status_code == 200, f"Failed POST /api/v1/spec/parse JSON: {res.text}"
    parsed_json = res.json()
    assert parsed_json["totalEndpoints"] == 6
    assert any(ep["path"] == "/api/v1/users/{user_id}/profile" for ep in parsed_json["endpoints"])
    print(f"  -> PASSED: JSON Spec parsed: {parsed_json['totalEndpoints']} endpoints identified.")

    print("\n[4.2] Testing POST /api/v1/spec/parse with YAML string ...")
    yaml_content = """
openapi: 3.0.1
info:
  title: Microservice Payments Gateway
  version: 2.1.0
  description: Internal checkout broker
servers:
  - url: https://payments.internal/v2
paths:
  /v2/checkout:
    post:
      summary: Initiate checkout session
      responses:
        '201':
          description: Session created
  /v2/refunds/{refund_id}:
    get:
      summary: Check refund status
      parameters:
        - name: refund_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Refund details
"""
    res = client.post("/api/v1/spec/parse", json={"specContent": yaml_content})
    assert res.status_code == 200, f"Failed POST /api/v1/spec/parse YAML: {res.text}"
    parsed_yaml = res.json()
    assert parsed_yaml["title"] == "Microservice Payments Gateway"
    assert parsed_yaml["totalEndpoints"] == 2
    print(f"  -> PASSED: YAML Spec parsed: '{parsed_yaml['title']}', {parsed_yaml['totalEndpoints']} endpoints.")

    # -------------------------------------------------------------
    # 5. Test POST /api/v1/spec/upload (Multipart File Upload)
    # -------------------------------------------------------------
    print("\n[5] Testing POST /api/v1/spec/upload with file ...")
    file_bytes = io.BytesIO(json.dumps(sample_spec).encode("utf-8"))
    res = client.post(
        "/api/v1/spec/upload",
        files={"file": ("openapi_test.json", file_bytes, "application/json")}
    )
    assert res.status_code == 200, f"Failed POST /api/v1/spec/upload: {res.text}"
    upload_res = res.json()
    assert upload_res["totalEndpoints"] == 6
    print(f"  -> PASSED: Multipart file uploaded and parsed: {upload_res['totalEndpoints']} endpoints.")

    # -------------------------------------------------------------
    # 6. Test GET /docs and GET /sandbox/docs
    # -------------------------------------------------------------
    print("\n[6.1] Testing GET /docs ...")
    res = client.get("/docs")
    assert res.status_code == 200, f"Failed GET /docs: {res.text}"
    assert "swagger-ui" in res.text.lower()
    print("  -> PASSED: Main Swagger UI documentation accessible.")

    print("\n[6.2] Testing GET /sandbox/docs ...")
    res = client.get("/sandbox/docs")
    assert res.status_code == 200, f"Failed GET /sandbox/docs: {res.text}"
    assert "swagger-ui" in res.text.lower()
    print("  -> PASSED: Sandbox Swagger UI documentation accessible.")

    # -------------------------------------------------------------
    # 7. Test POST /api/v1/scan/execute (Live Scan against Sandbox)
    # -------------------------------------------------------------
    print("\n[7] Testing POST /api/v1/scan/execute with full audit suite ...")
    scan_req = {
        "targetUrl": "http://127.0.0.1:8000/sandbox",
        "specContent": json.dumps(sample_spec),
        "checkAuth": True,
        "checkDataExposure": True,
        "checkRateLimit": True,
        "checkBola": True,
        "isSandboxConfirmed": True
    }
    res = client.post("/api/v1/scan/execute", json=scan_req)
    assert res.status_code == 200, f"Failed POST /api/v1/scan/execute: {res.text}"
    scan_res = res.json()
    
    assert "summary" in scan_res
    assert "findings" in scan_res
    assert "logs" in scan_res
    
    findings = scan_res["findings"]
    summary = scan_res["summary"]
    
    print(f"  -> Execution Completed in: {summary['duration']}")
    print(f"  -> Posture Score: {summary['securityScore']}%")
    print(f"  -> Total Findings Discovered: {len(findings)}")
    print(f"  -> Severity Breakdown: {summary['severityCounts']}")

    # Validate structure of each finding
    for f in findings:
        assert f["id"].startswith("VULN-")
        assert f["severity"] in ["Critical", "High", "Medium", "Low"]
        assert f["confidence"] in ["High", "Medium", "Low"]
        assert len(f["remediation"]["steps"]) > 0
        assert f["evidence"]["responseStatus"] > 0
        assert len(f["reproduction"]["curl"]) > 0

    print("  -> PASSED: Structured findings payload fully conforms to specification.")

    # -------------------------------------------------------------
    # 8. Test Safety Error Handling on External Public Targets
    # -------------------------------------------------------------
    print("\n[8] Testing Target Safety Constraint (External Host Rejection) ...")
    bad_req = {
        "targetUrl": "https://api.github.com",
        "specContent": json.dumps(sample_spec),
        "isSandboxConfirmed": True
    }
    res = client.post("/api/v1/scan/execute", json=bad_req)
    assert res.status_code == 400
    assert "Target safety" in res.json().get("detail", "")
    print("  -> PASSED: External public domain was strictly rejected.")

    # -------------------------------------------------------------
    # 9. Test Invalid JSON/YAML Parsing Errors
    # -------------------------------------------------------------
    print("\n[9] Testing Malformed Spec Error Handling ...")
    res = client.post("/api/v1/spec/parse", json={"specContent": "{ malformed json ::: "})
    assert res.status_code == 400
    print("  -> PASSED: Malformed specification returned clean 400 Bad Request.")

    print("\n" + "=" * 60)
    print("ALL 9 COMPREHENSIVE BACKEND TESTS COMPLETED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    run_comprehensive_test_suite()
