import time
import asyncio
import httpx
from typing import List, Dict, Any
from datetime import datetime, timezone
from ...models.security import Finding, DiscoveredEndpoint, CodeExample, ReferenceItem

async def run_rate_limit_checks(
    client: httpx.AsyncClient,
    base_url: str,
    endpoints: List[DiscoveredEndpoint],
    auth_headers: Dict[str, str]
) -> List[Finding]:
    """Audit endpoints for rate limiting controls, burst exhaustion, and resource throttling."""
    findings: List[Finding] = []
    
    # Target candidates for rate limiting checks
    rate_candidates = [
        ("/api/v1/transfers/quick", "POST", {"amount": 10, "recipient": "usr_102"}),
        ("/auth/login", "POST", {"username": "test_burst_user", "password": "wrong_password"}),
        ("/api/v1/auth/reset-password", "POST", {"email": "user@example.com"})
    ]

    for path, method, payload in rate_candidates:
        target = f"{base_url}{path}"
        try:
            # Dispatch burst of 8 rapid requests
            tasks = []
            for _ in range(8):
                if method == "POST":
                    tasks.append(client.post(target, json=payload, headers=auth_headers, timeout=2.5))
                else:
                    tasks.append(client.get(target, headers=auth_headers, timeout=2.5))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            valid_responses = [r for r in responses if isinstance(r, httpx.Response)]
            
            if not valid_responses:
                continue

            # Check if any request got 429 Too Many Requests or contains RateLimit headers
            has_429 = any(r.status_code == 429 for r in valid_responses)
            has_rate_header = any(
                "ratelimit" in k.lower() or "retry-after" in k.lower()
                for r in valid_responses
                for k in r.headers.keys()
            )

            # If all rapid burst requests succeeded with 200/202 and no rate-limit was enforced
            all_succeeded = all(r.status_code in (200, 201, 202, 401) for r in valid_responses) and len(valid_responses) >= 6

            if not has_429 and not has_rate_header and all_succeeded:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                finding_id = f"VULN-{int(time.time())}-RATELIM01"

                findings.append(
                    Finding(
                        id=finding_id,
                        title=f"Missing Rate Limiting on State-Changing Endpoint '{path}'",
                        cwe="CWE-770",
                        owaspCategory="API4:2023 Unrestricted Resource Consumption",
                        severity="Medium",
                        endpoint=path,
                        method=method,  # type: ignore
                        vulnerabilityType="Lack of Resources & Rate Limiting",
                        confidence="High",
                        status="Open",
                        timestamp=now_str,
                        description=f"Endpoint '{path}' accepted {len(valid_responses)} concurrent burst requests without throttling or returning HTTP 429 Too Many Requests.",
                        explanation="Unrestricted resource consumption allows attackers to perform brute force credential attacks, flood compute/database workers, or trigger race condition double-spending.",
                        evidence={
                            "requestPayload": f"{method} {path} (8 parallel concurrent burst requests)",
                            "responseStatus": valid_responses[0].status_code,
                            "responseBody": f"All {len(valid_responses)} burst requests processed successfully with status {valid_responses[0].status_code} and 0 rate limit headers returned.",
                            "headers": dict(valid_responses[0].headers)
                        },
                        reproduction={
                            "rawHttp": f"{method} {path} HTTP/1.1\nHost: {base_url.split('://')[-1]}\nContent-Type: application/json\n(x8 concurrent threads)",
                            "curl": f"for i in {{1..8}}; do\n  curl -X {method} \"{target}\" \\\n    -H \"Content-Type: application/json\" \\\n    -d '{str(payload)}' &\ndone"
                        },
                        remediation={
                            "summary": "Implement distributed IP-based and token-bucket rate limiting middleware (e.g., slowapi, Redis-backed rate limiter).",
                            "steps": [
                                "Configure max 10 requests per minute for sensitive endpoints.",
                                "Return HTTP 429 with 'Retry-After' header when quotas are exceeded."
                            ],
                            "codeExample": CodeExample(
                                language="python",
                                title="FastAPI SlowAPI Rate Limiter Guard",
                                code="from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/api/v1/transfers/quick')\n@limiter.limit('5/minute')\ndef transfer(request: Request):\n    return {'status': 'processed'}"
                            ),
                            "references": [
                                ReferenceItem(
                                    title="OWASP API Security Top 10 - Unrestricted Resource Consumption",
                                    url="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                                )
                            ]
                        }
                    )
                )
                break
        except Exception:
            continue

    return findings
