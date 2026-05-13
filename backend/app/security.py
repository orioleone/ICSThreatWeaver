"""Security utilities: API-key authentication, path validation, and URL validation."""

from __future__ import annotations

import hmac
import logging
import re
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .config import Settings, get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API-key authentication
# ---------------------------------------------------------------------------

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Security(_API_KEY_HEADER),
    settings: Settings = Depends(get_settings),
) -> None:
    """FastAPI dependency that enforces API-key auth when ``API_KEY`` is set.

    When ``API_KEY`` is empty (the default) this dependency is a no-op,
    allowing unauthenticated local development.
    """
    if not settings.API_KEY:
        return  # auth disabled — single-user / dev mode
    if not api_key or not hmac.compare_digest(api_key, settings.API_KEY):
        logger.warning("Request rejected — invalid or missing API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ---------------------------------------------------------------------------
# URL validation (SSRF guard)
# ---------------------------------------------------------------------------

def validate_https_url(url: str, allowed_hosts: list[str]) -> str:
    """Assert that *url* is HTTPS and targets an explicitly allowed host.

    Raises ``ValueError`` for any URL that fails these checks so callers can
    surface a 400 response rather than silently contacting arbitrary hosts.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:  # pragma: no cover
        raise ValueError(f"Malformed URL: {url}") from exc

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("URL contains no hostname.")

    if not any(
        hostname == host or hostname.endswith(f".{host}")
        for host in allowed_hosts
    ):
        raise ValueError(
            f"URL host '{hostname}' is not in the allowed list: {allowed_hosts}"
        )

    return url


# ---------------------------------------------------------------------------
# File-path validation (path-traversal guard)
# ---------------------------------------------------------------------------

# Reject strings containing null bytes or CR/LF which can be used to confuse
# path parsers or inject into log output.
# [RESOLVED] Centralized pattern for unsafe characters validation.
# This constant is also used in schemas.py for request validation.
# [SOURCE] Audit finding: Medium (M-2)
UNSAFE_CHARS_RE = re.compile(r"[\x00\r\n]")


def sanitize_file_path(raw: str, allowed_bases: list[Path]) -> Path:
    """Resolve *raw* to an absolute path and assert it is inside *allowed_bases*.

    Returns the resolved ``Path`` on success; raises ``ValueError`` otherwise.
    Callers should convert the ``ValueError`` to an HTTP 400 response.
    """
    if not raw or not raw.strip():
        raise ValueError("Path must not be empty.")

    if UNSAFE_CHARS_RE.search(raw):
        raise ValueError("Path contains unsafe control characters.")

    candidate = Path(raw).resolve()

    for base in allowed_bases:
        try:
            candidate.relative_to(base.resolve())
            return candidate
        except ValueError:
            continue

    raise ValueError(
        "Path is outside the allowed directories."
    )


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add hardened HTTP security headers to every response."""

    _HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        for header, value in self._HEADERS.items():
            response.headers[header] = value
        return response


# ---------------------------------------------------------------------------
# Rate-limiting middleware (in-memory sliding window)
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window, IP-keyed rate limiter with no external dependencies.

    Only ``/api/`` paths are counted; static and health endpoints are exempt.
    """

    def __init__(self, app: ASGIApp, max_requests: int = 100, window_seconds: int = 60) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = {}
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        # Only rate-limit API paths; the HTML frontend and /docs are exempt.
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        ip = (request.client.host if request.client else None) or "unknown"
        now = monotonic()
        cutoff = now - self.window

        with self._lock:
            bucket = self._buckets.get(ip, [])
            # Evict expired timestamps
            bucket = [t for t in bucket if t > cutoff]

            # [RESOLVED] Remove empty IP-bucket keys to prevent unbounded dict growth
            # under wide-scanning traffic patterns (e.g. ICS network reconnaissance).
            # [SOURCE] Audit finding: High (H-2)
            if not bucket and ip in self._buckets:
                del self._buckets[ip]

            if len(bucket) >= self.max_requests:
                logger.warning("Rate limit exceeded for %s", ip)
                return JSONResponse(
                    {"detail": "Too many requests. Please slow down."},
                    status_code=429,
                    headers={"Retry-After": str(self.window)},
                )
            bucket.append(now)
            self._buckets[ip] = bucket

        return await call_next(request)
