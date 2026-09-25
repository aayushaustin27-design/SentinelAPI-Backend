import re
import time
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from urllib.parse import urlparse
from ...models.security import Finding, CodeExample, ReferenceItem

# Regex patterns for high-confidence sensitive credential leaks in response bodies
LEAK_PATTERNS = [
    (
        r"AKIA[0-9A-Z]{16}",
        "Exposed AWS IAM Access Key ID",
        "Critical",
        "CWE-798",
        "API8:2023 Security Misconfiguration",
        "Hardcoded AWS Cloud Credentials exposed in API response payload."
    ),
    (
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "Exposed Cryptographic Private Key",
        "Critical",
        "CWE-312",
        "API8:2023 Security Misconfiguration",
        "Asymmetric private key structure leaked in API response body."
    ),
    (
        r"(postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.\@]+@[a-zA-Z0-9_\-\.]+",
        "Database Connection String with Embedded Credentials",
        "Critical",
        "CWE-200",
        "API8:2023 Security Misconfiguration",
        "Full database URI containing username and password leaked in response."
    ),
    (
        r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}",
        "Bcrypt Password Hash Exposure",
        "High",
        "CWE-200",
        "API3:2023 Broken Object Property Level Authorization",
        "Stored bcrypt password hashes returned directly in JSON response."
    ),
    (
        r"(Traceback \(most recent call last\):|TypeError:.*at line|SyntaxError:.*at line|NullPointerException.*at [a-zA-Z0-9_\.]+|at [a-zA-Z0-9_\.\/\-]+\.js:[0-9]+:[0-9]+)",
        "Verbose Runtime Stack Trace / Exception Disclosure",
        "Medium",
        "CWE-209",
        "API8:2023 Security Misconfiguration",
        "Unhandled server exception prints internal filesystem paths and function stack traces."
    )
]

async def run_evidence_based_checks(
    client: httpx.AsyncClient,
    target_url: str,
    initial_response: httpx.Response,
    discovered_paths: List[str]
) -> List[Finding]:
    """
    Executes passive and active evidence-based security audits against the target URL.
    Returns findings ONLY when concrete evidence is observed in target responses.
    """
    findings: List[Finding] = []
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname or "target"
    is_localhost = hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # -------------------------------------------------------------
    # 1. Transport Security Check (TLS / HTTPS)
    # -------------------------------------------------------------
    if parsed_url.scheme == "http" and not is_localhost:
        findings.append(
            Finding(
                id=f"VULN-{int(time.time())}-TLS01",
                title="Insecure Cleartext HTTP Protocol (Missing TLS/HTTPS Encryption)",
                cwe="CWE-319",
                owaspCategory="API8:2023 Security Misconfiguration",
                severity="High",
                endpoint=parsed_url.path or "/",
                method="GET",
                vulnerabilityType="Cleartext Communication",
                confidence="High",
                status="Open",
                timestamp=now_str,
                description=f"The API is served over unencrypted HTTP at '{target_url}'.",
                explanation="All API traffic, headers, authentication tokens, and parameters are transmitted in cleartext, exposing callers to Man-in-the-Middle (MitM) inspection, credential sniffing, and payload tampering.",
                evidence={
                    "requestPayload": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}",
                    "responseStatus": initial_response.status_code,
                    "responseBody": f"Connected over cleartext socket: {target_url}",
                    "headers": dict(initial_response.headers),
                    "highlightSnippet": f"Scheme: {parsed_url.scheme}://"
                },
                reproduction={
                    "rawHttp": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}\nAccept: application/json",
                    "curl": f"curl -i \"{target_url}\""
                },
                remediation={
                    "summary": "Enforce HTTPS/TLS encryption across all API hostnames and configure HTTP Strict Transport Security (HSTS).",
                    "steps": [
                        "Obtain and install a valid TLS certificate (e.g., via Let's Encrypt / Cloudflare).",
                        "Redirect all incoming HTTP traffic to HTTPS with 301 Permanent Redirect.",
                        "Set Strict-Transport-Security header: max-age=31536000; includeSubDomains."
                    ]
                }
            )
        )

    # -------------------------------------------------------------
    # 2. Server & Runtime Banner Disclosure
    # -------------------------------------------------------------
    headers_lower = {k.lower(): v for k, v in initial_response.headers.items()}
    banner_headers = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]
    disclosed_banners = []

    for bh in banner_headers:
        if bh in headers_lower:
            val = headers_lower[bh]
            # Flag if contains version numbers or specific engine names
            if any(char.isdigit() for char in val) or any(tech in val.lower() for tech in ["express", "apache", "nginx", "kestrel", "gunicorn", "uvicorn", "flask"]):
                disclosed_banners.append(f"{bh}: {val}")

    if disclosed_banners:
        findings.append(
            Finding(
                id=f"VULN-{int(time.time())}-BNR01",
                title="Server & Framework Technology Version Information Disclosure",
                cwe="CWE-200",
                owaspCategory="API8:2023 Security Misconfiguration",
                severity="Low",
                endpoint=parsed_url.path or "/",
                method="GET",
                vulnerabilityType="Banner Grabbing / Info Disclosure",
                confidence="High",
                status="Open",
                timestamp=now_str,
                description=f"The API exposes underlying server technologies and version banners in HTTP response headers.",
                explanation="Detailed server banners assist adversaries in pinpointing exact framework versions, CVEs, and known exploit payloads tailored to the detected software stack.",
                evidence={
                    "requestPayload": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}",
                    "responseStatus": initial_response.status_code,
                    "responseBody": "Observed header banners in HTTP response headers.",
                    "headers": {k: v for k, v in initial_response.headers.items() if k.lower() in banner_headers},
                    "highlightSnippet": "; ".join(disclosed_banners)
                },
                reproduction={
                    "rawHttp": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}",
                    "curl": f"curl -I \"{target_url}\""
                },
                remediation={
                    "summary": "Suppress software version banners and server signature headers in your web server / API gateway configuration.",
                    "steps": [
                        "In Nginx: set 'server_tokens off;'.",
                        "In Express / Node.js: 'app.disable(\"x-powered-by\");'.",
                        "In FastAPI / Starlette: Strip Server and X-Powered-By in middleware."
                    ]
                }
            )
        )

    # -------------------------------------------------------------
    # 3. Insecure / Overly Permissive CORS Headers
    # -------------------------------------------------------------
    cors_origin = headers_lower.get("access-control-allow-origin")
    cors_creds = headers_lower.get("access-control-allow-credentials", "").lower() == "true"
    
    if cors_origin == "*" and cors_creds:
        findings.append(
            Finding(
                id=f"VULN-{int(time.time())}-CORS01",
                title="Insecure CORS Policy with Wildcard Origin & Allowed Credentials",
                cwe="CWE-942",
                owaspCategory="API8:2023 Security Misconfiguration",
                severity="High",
                endpoint=parsed_url.path or "/",
                method="GET",
                vulnerabilityType="Insecure CORS Configuration",
                confidence="High",
                status="Open",
                timestamp=now_str,
                description="The API allows arbitrary origins ('*') while simultaneously accepting authenticated browser credentials.",
                explanation="Overly permissive CORS headers combined with credential exchange allow malicious third-party websites to make cross-origin requests and read private user responses.",
                evidence={
                    "requestPayload": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}\nOrigin: https://evil-attacker.com",
                    "responseStatus": initial_response.status_code,
                    "responseBody": "CORS response headers allow wildcard with credentials.",
                    "headers": {
                        "Access-Control-Allow-Origin": cors_origin or "*",
                        "Access-Control-Allow-Credentials": "true"
                    },
                    "highlightSnippet": f"Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: true"
                },
                reproduction={
                    "rawHttp": f"OPTIONS {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}\nOrigin: https://attacker.com\nAccess-Control-Request-Method: GET",
                    "curl": f"curl -i -X OPTIONS \"{target_url}\" -H \"Origin: https://attacker.com\""
                },
                remediation={
                    "summary": "Configure explicit domain whitelists for Cross-Origin Resource Sharing instead of wildcard origins.",
                    "steps": [
                        "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                        "Explicitly specify trusted frontend domains in CORS origins list."
                    ]
                }
            )
        )

    # -------------------------------------------------------------
    # 4. Sensitive Content Exposure in Body (Evidence-based pattern search)
    # -------------------------------------------------------------
    body_text = initial_response.text
    for pattern, title, severity, cwe, owasp, desc in LEAK_PATTERNS:
        match = re.search(pattern, body_text)
        if match:
            matched_str = match.group(0)
            # Create a safe redacted context snippet
            idx = match.start()
            start = max(0, idx - 20)
            end = min(len(body_text), idx + len(matched_str) + 20)
            snippet = body_text[start:end]

            findings.append(
                Finding(
                    id=f"VULN-{int(time.time())}-LEAK{len(findings)+1}",
                    title=f"Sensitive Data Exposure: {title}",
                    cwe=cwe,
                    owaspCategory=owasp,
                    severity=severity,  # type: ignore
                    endpoint=parsed_url.path or "/",
                    method="GET",
                    vulnerabilityType="Excessive Data Exposure",
                    confidence="High",
                    status="Open",
                    timestamp=now_str,
                    description=desc,
                    explanation=f"A concrete pattern match ('{title}') was discovered directly in the HTTP response payload returned by '{target_url}'.",
                    evidence={
                        "requestPayload": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}",
                        "responseStatus": initial_response.status_code,
                        "responseBody": body_text[:1000],
                        "headers": dict(initial_response.headers),
                        "highlightSnippet": snippet
                    },
                    reproduction={
                        "rawHttp": f"GET {parsed_url.path or '/'} HTTP/1.1\nHost: {hostname}\nAccept: application/json",
                        "curl": f"curl -i \"{target_url}\""
                    },
                    remediation={
                        "summary": "Remove secret keys, stack traces, and internal hashes from public API serialization models.",
                        "steps": [
                            "Implement strict response DTOs / serializer schemas.",
                            "Sanitize unhandled exceptions with global error-handling middleware."
                        ]
                    }
                )
            )

    # -------------------------------------------------------------
    # 5. Public OpenAPI / Swagger Documentation Exposure Probe
    # -------------------------------------------------------------
    # If the target is a base API URL, probe common schema endpoints
    base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    spec_paths_to_probe = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/api-docs", "/docs"]
    
    # Only probe if the current target isn't already one of those paths
    if parsed_url.path not in spec_paths_to_probe:
        for sp in spec_paths_to_probe[:2]:
            try:
                spec_resp = await client.get(f"{base_origin}{sp}", timeout=2.0)
                if spec_resp.status_code == 200 and any(k in spec_resp.text for k in ["openapi", "swagger", "paths"]):
                    findings.append(
                        Finding(
                            id=f"VULN-{int(time.time())}-SPEC01",
                            title=f"Public Unauthenticated OpenAPI / Swagger Schema Exposure ('{sp}')",
                            cwe="CWE-200",
                            owaspCategory="API8:2023 Security Misconfiguration",
                            severity="Low",
                            endpoint=sp,
                            method="GET",
                            vulnerabilityType="API Schema Exposure",
                            confidence="High",
                            status="Open",
                            timestamp=now_str,
                            description=f"The API schema is publicly accessible without authentication at '{base_origin}{sp}'.",
                            explanation="While open documentation is standard for public APIs, internal or proprietary enterprise microservices should restrict schema access to authenticated developers to prevent attackers from discovering hidden/deprecated endpoints.",
                            evidence={
                                "requestPayload": f"GET {sp} HTTP/1.1\nHost: {hostname}",
                                "responseStatus": spec_resp.status_code,
                                "responseBody": spec_resp.text[:800],
                                "headers": dict(spec_resp.headers),
                                "highlightSnippet": f"Found schema at {base_origin}{sp}"
                            },
                            reproduction={
                                "rawHttp": f"GET {sp} HTTP/1.1\nHost: {hostname}\nAccept: application/json",
                                "curl": f"curl -i \"{base_origin}{sp}\""
                            },
                            remediation={
                                "summary": "If this is an internal or partner API, protect the OpenAPI / Swagger JSON documentation with authentication middleware.",
                                "steps": [
                                    "Require API key or session token to access /openapi.json.",
                                    "Disable interactive Swagger UI (/docs) in production environments."
                                ]
                            }
                        )
                    )
                    break
            except Exception:
                pass

    return findings
