import time
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from ...models.security import Finding, DiscoveredEndpoint, CodeExample, ReferenceItem

async def run_auth_checks(
    client: httpx.AsyncClient,
    base_url: str,
    endpoints: List[DiscoveredEndpoint]
) -> List[Finding]:
    """Audit API endpoints for authentication misconfigurations and missing authorization controls."""
    findings: List[Finding] = []
    
    # 1. Check endpoints that might expose debug / system configurations without authentication
    candidate_paths = [
        "/api/v1/public/debug",
        "/api/v1/debug",
        "/api/v1/config",
        "/debug/vars",
        "/actuator/env"
    ]
    
    for path in candidate_paths:
        target = f"{base_url}{path}"
        try:
            resp = await client.get(target, timeout=3.0)
            if resp.status_code == 200:
                resp_text = resp.text[:1000]
                # If it looks like JSON config or debug payload
                if any(k in resp_text.lower() for k in ["debug", "env", "config", "version", "service"]):
                    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    finding_id = f"VULN-{int(time.time())}-AUTH01"
                    
                    findings.append(
                        Finding(
                            id=finding_id,
                            title="Unauthenticated Internal Diagnostic / Debug Endpoint Exposed",
                            cwe="CWE-306",
                            owaspCategory="API2:2023 Broken Authentication",
                            severity="High",
                            endpoint=path,
                            method="GET",
                            vulnerabilityType="Missing Authentication on Sensitive Endpoint",
                            confidence="High",
                            status="Open",
                            timestamp=now_str,
                            description=f"The endpoint '{path}' is accessible without any Authorization header or session token and returns internal diagnostic configuration.",
                            explanation="Diagnostic and debug endpoints allow unauthorized actors to map internal infrastructure, discover environment variables, and plan lateral movement without passing authentication checks.",
                            evidence={
                                "requestPayload": f"GET {path} HTTP/1.1\nHost: {base_url.split('://')[-1]}",
                                "responseStatus": resp.status_code,
                                "responseBody": resp_text,
                                "headers": dict(resp.headers)
                            },
                            reproduction={
                                "rawHttp": f"GET {path} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAccept: application/json",
                                "curl": f"curl -i -X GET \"{target}\""
                            },
                            remediation={
                                "summary": "Apply Zero-Trust authentication guards to all non-public endpoints and disable debug routes in production.",
                                "steps": [
                                    "Require valid Bearer token / IAM role for accessing diagnostic metrics.",
                                    "Disable debug routers when running in production environment."
                                ],
                                "codeExample": CodeExample(
                                    language="python",
                                    title="FastAPI Route Authentication Guard",
                                    code="@router.get('/api/v1/debug', dependencies=[Depends(require_admin_role)])\ndef get_debug_info():\n    return {'status': 'healthy'}"
                                ),
                                "references": [
                                    ReferenceItem(
                                        title="OWASP API Security Top 10 - Broken Authentication",
                                        url="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                                    )
                                ]
                            }
                        )
                    )
                    break
        except Exception:
            continue

    # 2. Test declared authenticated routes without credentials
    for ep in endpoints:
        if ep.authRequired or "profile" in ep.path or "order" in ep.path or "account" in ep.path:
            # Skip path template variables for unauthenticated check or substitute demo ID
            test_path = ep.path.replace("{user_id}", "usr_101").replace("{userId}", "usr_101").replace("{order_id}", "ord_9001")
            if "{" in test_path:
                continue
            
            target = f"{base_url}{test_path}"
            try:
                # Send request with invalid / malformed authorization header
                resp = await client.request(
                    method=ep.method,
                    url=target,
                    headers={"Authorization": "Bearer invalid_token_123"},
                    timeout=3.0
                )
                
                # If endpoint returned 200 with bogus token
                if resp.status_code == 200:
                    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    findings.append(
                        Finding(
                            id=f"VULN-{int(time.time())}-AUTH02",
                            title=f"Authentication Bypass on Protected Resource '{ep.path}'",
                            cwe="CWE-287",
                            owaspCategory="API2:2023 Broken Authentication",
                            severity="Critical",
                            endpoint=ep.path,
                            method=ep.method,
                            vulnerabilityType="Improper Authentication Validation",
                            confidence="High",
                            status="Open",
                            timestamp=now_str,
                            description=f"Endpoint '{ep.path}' accepted an invalid Bearer token and returned status 200 OK.",
                            explanation="The authentication middleware fails to cryptographically verify incoming token signatures or allows arbitrary strings to bypass access controls.",
                            evidence={
                                "requestPayload": f"{ep.method} {test_path} HTTP/1.1\nAuthorization: Bearer invalid_token_123",
                                "responseStatus": resp.status_code,
                                "responseBody": resp.text[:800],
                                "headers": dict(resp.headers)
                            },
                            reproduction={
                                "rawHttp": f"{ep.method} {test_path} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAuthorization: Bearer invalid_token_123",
                                "curl": f"curl -X {ep.method} \"{target}\" -H \"Authorization: Bearer invalid_token_123\""
                            },
                            remediation={
                                "summary": "Enforce strict cryptographic signature and expiration verification for all session tokens.",
                                "steps": [
                                    "Validate token against asymmetric public keys.",
                                    "Reject any request with status 401 Unauthorized if the token signature is invalid."
                                ]
                            }
                        )
                    )
            except Exception:
                continue

    return findings
