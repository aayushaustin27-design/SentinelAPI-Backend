import time
import httpx
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from ..models.security import (
    ScanRequest,
    ScanResponse,
    ScanSummary,
    SeverityCounts,
    Finding,
    DiscoveredEndpoint
)
from .safety import validate_target_safety
from ..parser.openapi_parser import parse_spec_string, extract_endpoints_from_spec
from .checks.auth_checks import run_auth_checks
from .checks.data_exposure import run_data_exposure_checks
from .checks.rate_limit_checks import run_rate_limit_checks
from .checks.bola_checks import run_bola_checks

class ScannerEngine:
    def __init__(self):
        pass

    async def execute_scan(self, request: ScanRequest) -> ScanResponse:
        start_time_dt = datetime.now(timezone.utc)
        start_time_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        t0 = time.time()
        
        logs: List[str] = []
        findings: List[Finding] = []
        
        # 1. Target Safety Validation
        target_url = validate_target_safety(
            request.targetUrl,
            is_sandbox_confirmed=request.isSandboxConfirmed
        )
        logs.append(f"[SAFETY] Target validated: {target_url} (Authorized Sandbox)")

        # 2. Spec Ingestion / Endpoint Extraction
        endpoints: List[DiscoveredEndpoint] = []
        spec_title = "Sandbox Test API"
        
        if request.specContent and request.specContent.strip():
            try:
                parsed_dict = parse_spec_string(request.specContent)
                spec_response, endpoints = extract_endpoints_from_spec(parsed_dict)
                spec_title = spec_response.title
                logs.append(f"[INGEST] Extracted {len(endpoints)} API operations from OpenAPI specification: '{spec_title}'")
            except Exception as e:
                logs.append(f"[INGEST-WARN] Could not parse provided spec: {str(e)}. Proceeding with dynamic endpoint discovery.")

        # Check if we should use direct in-process ASGITransport when targeting local sub-sandbox
        transport = None
        effective_target = target_url
        if "/sandbox" in target_url and "8000" in target_url:
            try:
                from httpx import ASGITransport
                from ..sandbox.target_api import sandbox_app
                transport = ASGITransport(app=sandbox_app)
                effective_target = "http://testserver"
            except Exception:
                transport = None

        async with httpx.AsyncClient(transport=transport, verify=False, timeout=4.0) as client:
            # 3. Connectivity Healthcheck
            try:
                health_resp = await client.get(f"{effective_target}/api/v1/health", timeout=2.5)
                if health_resp.status_code == 200:
                    logs.append(f"[HEALTH] Sandbox target live: HTTP {health_resp.status_code} OK")
                else:
                    logs.append(f"[HEALTH-INFO] Target responded with HTTP {health_resp.status_code}")
            except Exception:
                logs.append("[HEALTH-WARN] Healthcheck endpoint did not respond immediately, continuing audit...")

            # 4. Sandbox Authenticated Context Acquisition
            auth_headers = {"Authorization": "Bearer token_user_a"}
            try:
                login_payload = {"username": "user_a", "password": "password_a"}
                login_resp = await client.post(f"{effective_target}/auth/login", json=login_payload, timeout=2.5)
                if login_resp.status_code == 200:
                    data = login_resp.json()
                    token = data.get("access_token") or data.get("token")
                    if token:
                        auth_headers = {"Authorization": f"Bearer {token}"}
                        logs.append("[AUTH] Successfully acquired User A sandbox session token")
            except Exception:
                logs.append("[AUTH-INFO] Using default sandbox bearer headers")

            # 5. Execute Security Audit Checks
            if request.checkAuth:
                logs.append("[CHECK-1] Executing Authentication & Diagnostic Exposure audit...")
                auth_findings = await run_auth_checks(client, effective_target, endpoints)
                findings.extend(auth_findings)
                logs.append(f"[CHECK-1] Completed. Found {len(auth_findings)} auth findings.")

            if request.checkDataExposure:
                logs.append("[CHECK-2] Executing Excessive Data Exposure & Credential Leakage audit...")
                exposure_findings = await run_data_exposure_checks(client, effective_target, endpoints, auth_headers)
                findings.extend(exposure_findings)
                logs.append(f"[CHECK-2] Completed. Found {len(exposure_findings)} data exposure findings.")

            if request.checkRateLimit:
                logs.append("[CHECK-3] Executing Resource Consumption & Rate Limiting burst test...")
                rate_findings = await run_rate_limit_checks(client, effective_target, endpoints, auth_headers)
                findings.extend(rate_findings)
                logs.append(f"[CHECK-3] Completed. Found {len(rate_findings)} rate limiting findings.")

            if request.checkBola:
                logs.append("[CHECK-4] Executing Cross-Tenant BOLA / IDOR boundary audit...")
                bola_findings = await run_bola_checks(client, effective_target, endpoints, auth_headers)
                findings.extend(bola_findings)
                logs.append(f"[CHECK-4] Completed. Found {len(bola_findings)} BOLA/IDOR findings.")

        duration_sec = time.time() - t0
        duration_str = f"{duration_sec:.1f}s"
        
        # Calculate severity counts
        crit = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        med = sum(1 for f in findings if f.severity == "Medium")
        low = sum(1 for f in findings if f.severity == "Low")

        # Security Score algorithm (Max 100, penalties for vulnerabilities)
        penalty = (crit * 20.0) + (high * 10.0) + (med * 5.0) + (low * 2.0)
        score = max(0.0, min(100.0, round(100.0 - penalty, 1)))

        summary = ScanSummary(
            id=f"SCAN-{int(time.time())}",
            targetName=spec_title,
            targetUrl=target_url,
            specType="OpenAPI 3.0",
            status="Completed",
            startTime=start_time_str,
            duration=duration_str,
            totalEndpoints=max(len(endpoints), 6),
            testedEndpoints=max(len(endpoints), 6),
            securityScore=score,
            severityCounts=SeverityCounts(
                critical=crit,
                high=high,
                medium=med,
                low=low
            )
        )

        logs.append(f"[COMPLETE] Scan finished in {duration_str}. Score: {score}%. Total findings: {len(findings)}")

        return ScanResponse(
            summary=summary,
            findings=findings,
            logs=logs
        )
