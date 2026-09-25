import time
import httpx
from typing import List, Dict, Any
from datetime import datetime, timezone
from ...models.security import Finding, DiscoveredEndpoint, CodeExample, ReferenceItem

SENSITIVE_FIELD_PATTERNS = [
    ("password_hash", "Hashed / Stored Password Credential Leak", "Critical", "CWE-200"),
    ("internal_routing_key", "Internal Kafka / Message Broker Routing Metadata Leak", "High", "CWE-200"),
    ("stripe_customer_id", "Third-Party Payment Gateway Customer Identifier Leak", "Medium", "CWE-200"),
    ("ssn_last_four", "Personally Identifiable Information (SSN / PII) Exposure", "High", "CWE-359"),
    ("secret_key", "Server Secret Key Leakage", "Critical", "CWE-798"),
    ("stack_trace", "Raw Stack Trace / Runtime Exception Disclosure", "Low", "CWE-209")
]

async def run_data_exposure_checks(
    client: httpx.AsyncClient,
    base_url: str,
    endpoints: List[DiscoveredEndpoint],
    auth_headers: Dict[str, str]
) -> List[Finding]:
    """Audit endpoints for excessive data exposure, internal object leaking, and stack traces."""
    findings: List[Finding] = []
    
    # Test specific candidate endpoints or discovered endpoints
    test_endpoints = [
        "/api/v1/orders/ord_9001",
        "/api/v1/orders/ord_9002",
        "/api/v1/users/usr_101/profile"
    ]
    
    for ep in endpoints:
        path = ep.path.replace("{order_id}", "ord_9001").replace("{user_id}", "usr_101")
        if "{" not in path and path not in test_endpoints:
            test_endpoints.append(path)

    for path in test_endpoints:
        target = f"{base_url}{path}"
        try:
            resp = await client.get(target, headers=auth_headers, timeout=3.5)
            if resp.status_code == 200:
                body_text = resp.text
                
                for field_key, title, severity, cwe in SENSITIVE_FIELD_PATTERNS:
                    if field_key in body_text:
                        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        snippet = f'"{field_key}": ...'
                        
                        # Find snippet context
                        idx = body_text.find(field_key)
                        if idx != -1:
                            start = max(0, idx - 10)
                            end = min(len(body_text), idx + 80)
                            snippet = body_text[start:end].strip()

                        finding_id = f"VULN-{int(time.time())}-EXPO-{field_key[:4].upper()}"
                        
                        findings.append(
                            Finding(
                                id=finding_id,
                                title=f"Excessive Data Exposure: {title} on '{path}'",
                                cwe=cwe,
                                owaspCategory="API3:2023 Broken Object Property Level Authorization",
                                severity=severity,  # type: ignore
                                endpoint=path,
                                method="GET",
                                vulnerabilityType="Excessive Data Exposure (Over-fetching)",
                                confidence="High",
                                status="Open",
                                timestamp=now_str,
                                description=f"The endpoint '{path}' serializes internal sensitive database properties ('{field_key}') directly to the client.",
                                explanation="API implementations that rely on generic client-side filtering or return full ORM models without explicit DTO whitelisting expose sensitive credentials, payment tokens, and architecture details to potential attackers.",
                                evidence={
                                    "requestPayload": f"GET {path} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAuthorization: Bearer <VALID_SESSION_TOKEN>",
                                    "responseStatus": resp.status_code,
                                    "responseBody": body_text[:1200],
                                    "headers": dict(resp.headers),
                                    "highlightSnippet": snippet
                                },
                                reproduction={
                                    "rawHttp": f"GET {path} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nAuthorization: {auth_headers.get('Authorization', 'Bearer token_user_a')}\nAccept: application/json",
                                    "curl": f"curl -X GET \"{target}\" \\\n  -H \"Authorization: {auth_headers.get('Authorization', 'Bearer token_user_a')}\""
                                },
                                remediation={
                                    "summary": "Implement explicit response schemas / DTOs using Pydantic, Zod, or serializer whitelists to prevent over-exposure.",
                                    "steps": [
                                        f"Exclude '{field_key}' and internal fields from public response models.",
                                        "Use strict schema response_model in endpoint decorators.",
                                        "Ensure sensitive credentials and routing metadata are never serialized to external consumers."
                                    ],
                                    "codeExample": CodeExample(
                                        language="python",
                                        title="FastAPI Explicit Response Model (DTO)",
                                        code="class PublicOrderResponse(BaseModel):\n    order_id: str\n    item: str\n    amount: float\n    status: str\n    # Internal fields like password_hash and internal_routing_key are strictly excluded\n\n@app.get('/api/v1/orders/{order_id}', response_model=PublicOrderResponse)\ndef get_order(order_id: str):\n    return db.get_order(order_id)"
                                    ),
                                    "references": [
                                        ReferenceItem(
                                            title="OWASP API Security Top 10 - Broken Object Property Level Authorization",
                                            url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                                        )
                                    ]
                                }
                            )
                        )
                        break
        except Exception:
            continue

    return findings
