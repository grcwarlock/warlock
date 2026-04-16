"""Security middleware for the Warlock GRC API.

Adds rate limiting, security headers, and request audit logging
to all API responses. Ported from v1's production hardening.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import HTTPException
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
    "/api/v1/auth/login": (10, 5),  # stricter: 10/min + 5 burst
    "/api/v1/auth/register": (5, 2),  # very strict: 5/min + 2 burst
    # F11: brute-force / credential-stuffing protection
    "/api/v1/auth/mfa/verify": (5, 2),  # 6-digit TOTP; keep tight
    "/api/v1/auth/refresh": (10, 5),  # refresh-token replay
    "/api/v1/auth/change-password": (5, 2),  # existing-password guessing
    "/api/v1/auth/password-reset": (5, 2),  # token harvesting / enumeration
    "/api/v1/auth/sso/login": (20, 5),  # SSO state exhaustion
    "/api/v1/auth/sso/callback": (20, 5),  # SSO callback abuse
    "/api/v1/scim/Users": (30, 10),  # SCIM Users create/list bulk
    "/api/v1/ingest/webhook": (100, 20),  # generic webhook ingest
    "/api/v1/webhooks/jira": (60, 10),  # Jira bidirectional webhook
    "/api/v1/trust/request-access": (10, 3),  # public endpoint, strict
    "/api/v1/ai/reason": (30, 5),  # expensive AI reasoning calls
    "/api/v1/ai/converse": (30, 5),  # expensive AI conversation calls
    "/api/v1/risk/analyze": (10, 2),  # Monte Carlo simulation
    "/api/v1/pipeline/collect": (5, 2),  # full pipeline run
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Counter-based rate limiter per API key or client IP.

    Uses the shared cache backend (in-memory or Redis) for counter storage.
    When Redis is configured via WLK_CACHE_URL, rate limits are enforced
    consistently across all workers.

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
        self.window_seconds = 60

    def _client_key(self, request: Request) -> str:
        """Derive a rate-limit key from the request.

        F26: Combine IP and API key so the budget is enforced per
        (ip, key) tuple. A caller cannot double their allowance by
        alternating between sending and omitting the key — both bursts
        share the same bucket.
        """
        import hashlib

        client = request.client
        host = client.host if client else "unknown"
        api_key = request.headers.get("x-api-key", "")
        key_part = hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key else "anon"
        return f"ip:{host}|key:{key_part}"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        from warlock.utils.cache import MemoryCache, get_cache

        cache = get_cache()
        key = self._client_key(request)

        # Determine whether rate limits are enforced per-worker (in-memory)
        # or globally (Redis).  When MemoryCache is in use each Uvicorn worker
        # maintains its own counters, so a client can effectively multiply its
        # allowed request budget by the number of workers.  The scope header
        # lets API consumers know which mode is active.  See H-24.
        using_memory = isinstance(cache, MemoryCache)
        scope = "worker" if using_memory else "global"

        # Apply per-endpoint limits when defined; fall back to instance defaults
        path = request.url.path
        if path in _ENDPOINT_LIMITS:
            rpm, burst = _ENDPOINT_LIMITS[path]
        else:
            rpm, burst = self.requests_per_minute, self.burst

        max_allowed = rpm + burst
        cache_key = f"ratelimit:{key}"
        count = cache.increment(cache_key, ttl=self.window_seconds)

        if count > max_allowed:
            log.warning(
                "Rate limit exceeded for %s (%d requests in window, scope=%s)",
                key,
                count,
                scope,
            )
            return Response(
                content='{"detail":"Rate limit exceeded","scope":"' + scope + '"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(self.window_seconds),
                    "X-RateLimit-Limit": str(max_allowed),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(self.window_seconds),
                    "X-RateLimit-Scope": scope,
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_allowed)
        response.headers["X-RateLimit-Remaining"] = str(max(0, max_allowed - count))
        # Reset is the number of seconds until the current window expires.
        # The exact window start is unknown (counter-based), so we report
        # the full window duration as a conservative upper bound.
        response.headers["X-RateLimit-Reset"] = str(self.window_seconds)
        response.headers["X-RateLimit-Scope"] = scope
        if using_memory:
            response.headers["X-RateLimit-Warning"] = "per-worker"
        return response


# ---------------------------------------------------------------------------
# Request Body Size Enforcement
# ---------------------------------------------------------------------------

# Maximum request body size in bytes (10 MB default).
# Content-Length alone is insufficient — chunked Transfer-Encoding bypasses it.
_MAX_BODY_BYTES = 10 * 1024 * 1024


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """Enforce a hard cap on request body size regardless of Transfer-Encoding.

    The Content-Length header is advisory and absent on chunked requests.
    This middleware wraps the receive callable to track actual bytes read
    and aborts with 413 if the limit is exceeded.
    """

    def __init__(self, app, max_bytes: int = _MAX_BODY_BYTES) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Fast-reject based on Content-Length when present
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    return Response(
                        content='{"detail":"Request body too large"}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass  # malformed header — let body-reading check handle it

        # Wrap the ASGI receive to count actual bytes (catches chunked encoding)
        bytes_read = 0
        max_bytes = self.max_bytes
        original_receive = request._receive  # type: ignore[attr-defined]

        async def limited_receive():
            nonlocal bytes_read
            message = await original_receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                bytes_read += len(body)
                if bytes_read > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Request body too large",
                    )
            return message

        request._receive = limited_receive  # type: ignore[attr-defined]

        try:
            return await call_next(request)
        except HTTPException as exc:
            if exc.status_code == 413:
                return Response(
                    content='{"detail":"Request body too large"}',
                    status_code=413,
                    media_type="application/json",
                )
            raise


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------


def _generate_nonce() -> str:
    """Generate a cryptographic nonce for CSP inline script whitelisting."""
    import base64
    import secrets

    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject standard security headers into every response.

    GAP-101: Tightened CSP from bare ``default-src 'self'`` to a
    granular directive set.  A per-request nonce is generated and
    stored on ``request.state.csp_nonce`` for any inline scripts that
    require whitelisting.
    """

    # N35 hardening:
    # - HSTS now includes ``preload`` directive
    # - Cross-Origin-Opener-Policy / Embedder-Policy / Resource-Policy added
    #   for Spectre / cross-site isolation
    # - Permissions-Policy expanded with deny-all on commonly-abused features
    # - Server header explicitly blanked to avoid uvicorn version disclosure
    _STATIC_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
            "interest-cohort=(), accelerometer=(), gyroscope=(), magnetometer=(), "
            "midi=(), serial=(), bluetooth=(), screen-wake-lock=()"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-site",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Server": "",  # blank server header (don't leak uvicorn version)
    }

    _CSP_TEMPLATE = (
        "default-src 'self'; "
        "script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'nonce-{nonce}'; "  # N35: nonce styles instead of unsafe-inline
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "upgrade-insecure-requests"
    )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate a per-request nonce and expose it via request.state
        nonce = _generate_nonce()
        request.state.csp_nonce = nonce

        response: Response = await call_next(request)

        for header, value in self._STATIC_HEADERS.items():
            response.headers.setdefault(header, value)

        # Set CSP with the per-request nonce
        response.headers.setdefault(
            "Content-Security-Policy",
            self._CSP_TEMPLATE.format(nonce=nonce),
        )

        # API responses should never be cached by default
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")

        return response


# ---------------------------------------------------------------------------
# Request Audit Logging
# ---------------------------------------------------------------------------

# Paths that generate high-volume, low-value audit entries
_SKIP_PATHS = frozenset(
    {
        "/api/v1/health",
        "/health",
        "/healthz",
        "/readyz",
        "/health/live",
        "/health/ready",
        "/docs",
        "/openapi.json",
        "/redoc",
    }
)


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


# Query param names whose VALUES must never appear in audit logs (F20).
# Values are replaced with "[redacted]" while the key is preserved so that
# the audit record is still meaningful ("caller passed ?token=" vs. nothing).
_AUDIT_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "code",
        "state",
        "nonce",
        "api_key",
        "apikey",
        "secret",
        "password",
        "reset_token",
        "session_id",
        "assertion",  # SAML / JWT-bearer
    }
)


def _scrub_query_for_audit(raw: str) -> str:
    """Redact sensitive query parameter VALUES while preserving keys."""
    if not raw:
        return ""
    from urllib.parse import parse_qsl, urlencode

    try:
        pairs = parse_qsl(raw, keep_blank_values=True)
    except Exception:
        return "[unparseable]"
    scrubbed = [
        (k, "[redacted]" if k.lower() in _AUDIT_SENSITIVE_QUERY_KEYS else v) for k, v in pairs
    ]
    return urlencode(scrubbed)


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
                "query": _scrub_query_for_audit(str(request.url.query)),
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
    # S-6: Warn if running production without Redis-backed shared cache
    import os

    wlk_env = os.environ.get("WLK_ENV", "").strip().lower()
    cache_url = os.environ.get("WLK_CACHE_URL", "").strip()
    if wlk_env == "production" and not cache_url:
        log.error(
            "PRODUCTION ERROR: No cache URL configured (WLK_CACHE_URL). "
            "Rate limiter is running in per-process in-memory mode — each worker "
            "maintains independent counters, so effective rate limits are multiplied "
            "by the number of workers (H-24). "
            "Configure WLK_CACHE_URL to a Redis instance for production deployments."
        )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestBodyLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestAuditMiddleware)
