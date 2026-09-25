from urllib.parse import urlparse
from fastapi import HTTPException
import socket

def validate_target_safety(target_url: str, is_sandbox_confirmed: bool = True) -> str:
    """
    Validates target URL format and enforces safe protocol restrictions.
    Allows scanning both public APIs (e.g. Open-Meteo, public REST APIs) and local sandbox targets.
    Prevents invalid schemes and malformed URLs.
    """
    if not target_url or not target_url.strip():
        raise HTTPException(
            status_code=400,
            detail="Target URL cannot be empty."
        )

    cleaned = target_url.strip()
    # Auto-prefix http/https if missing
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid URL protocol '{parsed.scheme}://'. SentinelAPI supports HTTP and HTTPS APIs."
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve target hostname from URL."
        )

    return cleaned
