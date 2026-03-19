"""Security middleware for the Warlock GRC API.

Adds rate limiting, security headers, and request audit logging
to all API responses. Ported from v1's production hardening.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


# Per-endpoint rate limits: path -> (requests_per_minute, burst)
# These override the default limits for security-sensitive endpoints.
_ENDPOINT_LIMITS: dict[str, tuple[int, int]] = {
    "/api/v1/auth/login": (10, 5),           # stricter: 10/min + 5 burst
    "/api/v1/auth/register": (5, 2),         # very strict: 5/min + 2 burst
    "/api/v1/trust/request-access": (10, 3), # public endpoint, strict
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limiter per API key or client IP.

    Uses an in-memory sliding window. For multi-process deployments,
    swap the storage backend to Redis.

    Per-endpoint overrides are defined in ``_ENDPOINT_LIMITS``.
    """

    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        burst: int = 10,
    ) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self.window_seconds = 60.0
        # client_key -> list of request timestamps
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

        import multiprocessing
        workers = multiprocessing.cpu_count()  # rough proxy for worker count
        if workers > 1:
            log.warning(
                "In-memory rate limiter is per-process. With multiple workers, "
                "effective rate limit is %dx. Use Redis-backed limiter for production.",
                workers,
            )

    def _client_key(self, request: Request) -> str:
        """Derive a rate-limit key from the request.

        Prefers the X-Api-Key header (hashed identity) over client IP
        so that authenticated clients share a key across IPs.
        """
        api_key = request.headers.get("x-api-key")
        if api_key:
            # Hash the key — never use raw key material as identity (H-4 fix)
            import hashlib
            return f"key:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
        # Fall back to IP
        client = request.client
        host = client.host if client else "unknown"
        return f"ip:{host}"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        key = self._client_key(request)
        now = time.monotonic()

        # Apply per-endpoint limits when defined; fall back to instance defaults
        path = request.url.path
        if path in _ENDPOINT_LIMITS:
            rpm, burst = _ENDPOINT_LIMITS[path]
        else:
            rpm, burst = self.requests_per_minute, self.burst

        with self._lock:
            # Prune timestamps outside the window
            window = self._windows[key]
            cutoff = now - self.window_seconds
            self._windows[key] = window = [t for t in window if t > cutoff]

            # Check if over limit (allow burst above steady rate)
            max_allowed = rpm + burst
            if len(window) >= max_allowed:
                # Calculate Retry-After from oldest request in window
                retry_after = int(self.window_seconds - (now - window[0])) + 1
                retry_after = max(retry_after, 1)
                log.warning(
                    "Rate limit exceeded for %s (%d requests in window)",
                    key,
                    len(window),
                )
                return Response(
                    content='{"detail":"Rate limit exceeded"}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": str(retry_after)},
                )

            window.append(now)

            # Periodically evict idle clients to prevent memory leak
            if len(self._windows) > 1000:
                empty_keys = [k for k, v in self._windows.items() if not v]
                for k in empty_keys:
                    del self._windows[k]

        return await call_next(request)


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject standard security headers into every response."""

    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        for header, value in self.HEADERS.items():
            response.headers.setdefault(header, value)

        # API responses should never be cached by default
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")

        return response


# ---------------------------------------------------------------------------
# Request Audit Logging
# ---------------------------------------------------------------------------

# Paths that generate high-volume, low-value audit entries
_SKIP_PATHS = frozenset({
    "/api/v1/health",
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
})


class RequestAuditMiddleware(BaseHTTPMiddleware):
    """Log all API requests to the audit trail.

    Records timestamp, method, path, authenticated identity,
    response status code, and duration in milliseconds.

    When an AuditTrail writer is available, entries are persisted
    to the audit_entries table. Otherwise they are emitted via
    the standard logger.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip noisy endpoints
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        from warlock.logging_config import new_correlation_id
        cid = new_correlation_id()

        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 2)

        response.headers["X-Correlation-ID"] = cid

        # Identify the caller
        identity = _extract_identity(request)

        log.info(
            "api_request method=%s path=%s user=%s status=%d duration_ms=%.2f",
            request.method,
            request.url.path,
            identity,
            response.status_code,
            duration_ms,
        )

        # Persist to audit trail if available (best-effort, never block)
        try:
            _persist_audit_entry(request, response, identity, duration_ms)
        except Exception:
            # Audit persistence must never break the request
            log.debug("Failed to persist request audit entry", exc_info=True)

        return response


def _extract_identity(request: Request) -> str:
    """Pull caller identity from headers (api key prefix or JWT sub)."""
    api_key = request.headers.get("x-api-key")
    if api_key:
        import hashlib
        return f"apikey:{hashlib.sha256(api_key.encode()).hexdigest()[:12]}"

    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        # Don't decode — just note a bearer token was used
        return "bearer_token"

    client = request.client
    host = client.host if client else "unknown"
    return f"anonymous:{host}"


def _persist_audit_entry(
    request: Request,
    response: Response,
    identity: str,
    duration_ms: float,
) -> None:
    """Best-effort write to the AuditEntry table."""
    try:
        from warlock.db.audit import AuditTrail
        from warlock.db.engine import get_session
    except ImportError:
        return

    with get_session() as session:
        trail = AuditTrail(session)
        trail.record(
            action="api_request",
            entity_type="http_request",
            entity_id=request.url.path,
            actor=identity,
            metadata={
                "method": request.method,
                "path": str(request.url.path),
                "query": str(request.url.query) if request.url.query else "",
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------


def register_middleware(app) -> None:
    """Add all security middleware to a FastAPI application.

    Call order matters — outermost middleware runs first. We want:
      1. Security headers (always applied)
      2. Rate limiting (reject before processing)
      3. Audit logging (captures final status)

    Starlette processes middleware in reverse registration order,
    so we register in reverse: audit first, rate limit second, headers last.
    """
    # S-6: Warn if running production without Redis-backed rate limiter
    import os
    wlk_env = os.environ.get("WLK_ENV", "").strip().lower()
    redis_url = os.environ.get("WLK_QUEUE_URL", "").strip()
    if wlk_env == "production" and not redis_url:
        log.warning(
            "PRODUCTION WARNING: No Redis URL configured (WLK_QUEUE_URL). "
            "Rate limiter is running in per-process in-memory mode. "
            "Rate limits will not be shared across workers. "
            "Configure WLK_QUEUE_URL to a Redis instance for production deployments."
        )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestAuditMiddleware)
