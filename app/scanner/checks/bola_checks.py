import time
import httpx
from typing import List, Dict, Any
from datetime import datetime, timezone
from ...models.security import Finding, DiscoveredEndpoint, CodeExample, ReferenceItem

async def run_bola_checks(
    client: httpx.AsyncClient,
    base_url: str,
    endpoints: List[DiscoveredEndpoint],
    user_a_headers: Dict[str, str]
) -> List[Finding]:
    """
    Test BOLA / IDOR horizontal authorization boundaries specifically against the sandbox target.
    Attempts to read User B's object while authenticated as User A.
    """
    findings: List[Finding] = []
    
    # Candidate BOLA endpoints in the sandbox API
    candidate_tests = [
        {
            "path": "/api/v1/users/usr_102/profile",
            "method": "GET",
            "target_user_id": "usr_102",
            "expected_leak_keyword": "user_b",
            "display_name": "User B (Bob Smith)",
            "object_type": "User Profile"
        },
        {
            "path": "/api/v1/accounts/usr_102/balance",
            "method": "GET",
            "target_user_id": "usr_102",
            "expected_leak_keyword": "balance",
            "display_name": "User B Private Ledger",
            "object_type": "Financial Account"
        }
    ]

    for test in candidate_tests:
        target = f"{base_url}{test['path']}"
        try:
            resp = await client.get(target, headers=user_a_headers, timeout=3.5)
            
            # If User A's token succeeded in retrieving User B's record (HTTP 200)
            if resp.status_code == 200 and test["expected_leak_keyword"] in resp.text.lower():
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                finding_id = f"VULN-{int(time.time())}-BOLA01"
                
                resp_snippet = resp.text[:900]
                
                findings.append(
                    Finding(
                        id=finding_id,
                        title=f"Broken Object Level Authorization (BOLA / IDOR) on '{test['path']}'",
                        cwe="CWE-284",
                        cve="CVE-2026-BOLA-01",
                        owaspCategory="API1:2023 Broken Object Level Authorization",
                        severity="Critical",
                        endpoint=test["path"],
                        method=test["method"],  # type: ignore
                        vulnerabilityType="Authorization Bypass (BOLA / IDOR)",
                        confidence="High",
                        status="Open",
                        timestamp=now_str,
                        description=f"Endpoint '{test['path']}' returned private {test['object_type']} data for User B ('{test['target_user_id']}') while caller was authenticated as User A.",
                        explanation="The backend retrieves resources directly by path parameter ID without validating that the authenticated caller's identity/tenant context owns or has explicit permission to access the requested object. An attacker can iterate IDs to access all system records.",
                        evidence={
                            "requestPayload": f"GET {test['path']} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAuthorization: {user_a_headers.get('Authorization', 'Bearer token_user_a')}",
                            "responseStatus": resp.status_code,
                            "responseBody": resp_snippet,
                            "headers": dict(resp.headers),
                            "highlightSnippet": f"\"{test['expected_leak_keyword']}\": (User B Data Returned to User A)"
                        },
                        reproduction={
                            "rawHttp": f"GET {test['path']} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAuthorization: {user_a_headers.get('Authorization', 'Bearer token_user_a')}\nAccept: application/json",
                            "curl": f"curl -X GET \"{target}\" \\\n  -H \"Authorization: {user_a_headers.get('Authorization', 'Bearer token_user_a')}\" \\\n  -H \"Accept: application/json\"",
                            "notes": f"Authenticate as User A (token_user_a), then supply user_id='{test['target_user_id']}' in the URL path."
                        },
                        remediation={
                            "summary": "Enforce object tenancy checks by verifying that the requested resource ID belongs to the authenticated user's session context.",
                            "steps": [
                                "Extract the verified user ID from the request context / JWT claims.",
                                "Verify ownership in the database query (e.g., WHERE id = :resource_id AND owner_user_id = :current_user_id).",
                                "Return HTTP 403 Forbidden or 404 Not Found if the resource does not belong to the caller."
                            ],
                            "codeExample": CodeExample(
                                language="python",
                                title="Zero-Trust Object Tenancy Validation",
                                code="from fastapi import HTTPException, status, Depends\n\n@app.get('/api/v1/users/{user_id}/profile')\ndef get_user_profile(user_id: str, current_user = Depends(get_current_user)):\n    # Strict Object Ownership Validation\n    if current_user['id'] != user_id and current_user.get('role') != 'admin':\n        raise HTTPException(\n            status_code=status.HTTP_403_FORBIDDEN,\n            detail='Access denied: Cannot access another user profile'\n        )\n    return db.get_profile(user_id)"
                            ),
                            "references": [
                                ReferenceItem(
                                    title="OWASP API Security Top 10 - Broken Object Level Authorization (BOLA)",
                                    url="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                )
                            ]
                        }
                    )
                )
        except Exception:
            continue

    return findings
