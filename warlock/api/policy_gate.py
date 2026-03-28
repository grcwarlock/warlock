"""OPA policy enforcement middleware and IP allowlist for API operations.

Calls an OPA server to evaluate whether an API operation is allowed
based on custom policy rules. Falls back to allow/deny based on
``fail_mode`` when OPA is unreachable.

SAC-1: IP allowlist enforcement — checks client IP against the
``ip_allowlist`` database table when ``ip_allowlist_enabled`` is True.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import HTTPException, Request, status

from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Health endpoint paths that bypass all policy checks (including IP allowlist)
# ---------------------------------------------------------------------------

_HEALTH_PATHS = frozenset({"/health", "/healthz", "/readyz"})


def _is_health_endpoint(path: str) -> bool:
    """Return True for health/readiness endpoints that skip policy checks."""
    return path in _HEALTH_PATHS or path.endswith("/health")


class PolicyGate:
    """OPA policy enforcement for API operations.

    Parameters:
        opa_url: OPA decision endpoint (e.g. ``http://localhost:8181/v1/data/warlock/allow``).
        fail_mode: ``"open"`` (allow if OPA unreachable) or ``"closed"`` (deny).
    """

    def __init__(
        self,
        opa_url: str | None = None,
        fail_mode: str | None = None,
    ):
        from warlock.config import get_settings

        settings = get_settings()
        self.opa_url = opa_url or settings.opa_url
        # S-2: Default to fail-closed. Explicit parameter overrides settings.
        self.fail_mode = fail_mode or settings.opa_fail_mode or "closed"
        # S-2: Warn when fail-open in production
        if settings.env == "production" and self.fail_mode == "open":
            log.critical(
                "GAP-061: OPA policy gate is set to fail-open in PRODUCTION. "
                "This means OPA outages will bypass ALL policy enforcement. "
                "Set WLK_OPA_FAIL_MODE=closed for production."
            )
        # GAP-061: Also warn about opa_compliance_fail_mode
        if settings.opa_compliance_fail_mode == "open":
            if settings.env != "development":
                log.critical(
                    "GAP-061: OPA compliance fail_mode is 'open' in a non-development "
                    "environment (env=%s). All requests pass when OPA is unavailable.",
                    settings.env,
                )
        self.enabled = bool(self.opa_url)
        self._session = None

    def _get_http_session(self):
        """Lazy-create an httpx or urllib session."""
        if self._session is not None:
            return self._session
        try:
            import httpx

            self._session = httpx.Client(timeout=5.0)
        except ImportError:
            self._session = None
        return self._session

    async def evaluate(
        self,
        request: Request,
        user: Any,
        action: str,
    ) -> bool:
        """Ask OPA if this operation is allowed.

        Input to OPA::

            {
                "input": {
                    "user": {"email": "...", "role": "..."},
                    "action": "read",
                    "resource": "/api/v1/findings",
                    "method": "GET",
                    "path": "/api/v1/findings"
                }
            }

        Returns True if allowed.
        """
        if not self.enabled:
            return True

        user_email = getattr(user, "email", "unknown") if user else "anonymous"
        user_role = getattr(user, "role", "unknown") if user else "anonymous"

        opa_input = {
            "input": {
                "user": {
                    "email": user_email,
                    "role": user_role,
                },
                "action": action,
                "resource": str(request.url.path),
                "method": request.method,
                "path": str(request.url.path),
            }
        }

        try:
            result = await self._call_opa(opa_input)
            # OPA returns {"result": true/false} or {"result": {"allow": true/false}}
            if isinstance(result, bool):
                return result
            if isinstance(result, dict):
                return result.get("allow", result.get("result", False))
            return bool(result)
        except Exception as exc:
            if self.fail_mode == "open":
                # GAP-061: Clearly warn when OPA bypass is active
                log.warning(
                    "OPA fail-open mode active — all requests pass when OPA is "
                    "unavailable (error: %s)",
                    exc,
                )
                return True
            log.warning("OPA evaluation failed: %s (fail_mode=%s)", exc, self.fail_mode)
            return False

    async def _call_opa(self, opa_input: dict) -> Any:
        """Make HTTP call to OPA server."""
        import urllib.request
        import urllib.error

        # Try httpx first (async-friendly), fall back to urllib
        client = self._get_http_session()
        if client is not None:
            try:
                resp = client.post(self.opa_url, json=opa_input)
                resp.raise_for_status()
                data = resp.json()
                return data.get("result", False)
            except Exception as exc:
                raise RuntimeError(f"OPA request failed: {exc}") from exc
        else:
            # Fallback to stdlib urllib
            req = urllib.request.Request(
                self.opa_url,
                data=json.dumps(opa_input).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("result", False)
            except urllib.error.URLError as exc:
                raise RuntimeError(f"OPA request failed: {exc}") from exc

    def as_dependency(self, action: str) -> Callable:
        """Return a FastAPI dependency that enforces the policy.

        Usage::

            gate = PolicyGate()

            @app.get("/api/v1/findings")
            async def list_findings(
                _allowed = Depends(gate.as_dependency("read_findings")),
            ):
                ...
        """
        gate = self

        async def _enforce(request: Request):
            if not gate.enabled:
                return True

            # Try to get the current user from request state
            user = getattr(request.state, "user", None)
            allowed = await gate.evaluate(request, user, action)
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Policy denied: action={action}",
                )
            return True

        return _enforce


# ---------------------------------------------------------------------------
# IP Allowlist Enforcement (SAC-1)
# ---------------------------------------------------------------------------


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP from the request.

    Respects X-Forwarded-For (first entry) when behind a reverse proxy,
    falling back to the direct client address.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # X-Forwarded-For: client, proxy1, proxy2 — take the leftmost
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"


async def check_ip_allowlist(request: Request) -> None:
    """Enforce IP allowlist if enabled in settings.

    Checks the client IP against active, non-expired CIDR entries in
    the ``ip_allowlist`` database table. Raises HTTP 403 if the IP
    is not in any allowlisted range.

    Skips the check for health endpoints so that load balancer and
    Kubernetes probes are never blocked.

    SAC-1: IP allowlist enforcement.
    """
    from warlock.config import get_settings

    settings = get_settings()
    if not settings.ip_allowlist_enabled:
        return

    path = request.url.path
    if _is_health_endpoint(path):
        return

    client_ip_str = _get_client_ip(request)

    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        log.warning("IP allowlist: could not parse client IP %r — denying", client_ip_str)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: unrecognized client address",
        )

    # Query active allowlist entries from DB
    from warlock.db.engine import get_session
    from warlock.db.models import IPAllowlistEntry

    with get_session() as db:
        entries = (
            db.query(IPAllowlistEntry)
            .filter(IPAllowlistEntry.active == True)  # noqa: E712
            .all()
        )

        now = datetime.now(timezone.utc)
        for entry in entries:
            # Skip expired entries
            if entry.expires_at:
                expires = ensure_aware(entry.expires_at)
                if expires < now:
                    continue

            try:
                network = ipaddress.ip_network(entry.cidr, strict=False)
                if client_ip in network:
                    log.debug(
                        "IP allowlist: %s matched CIDR %s (%s)",
                        client_ip_str,
                        entry.cidr,
                        entry.description or "no description",
                    )
                    return  # Allowed
            except ValueError:
                log.warning(
                    "IP allowlist: invalid CIDR %r in entry %s — skipping",
                    entry.cidr,
                    entry.id,
                )
                continue

    # No matching entry found — deny
    log.warning("IP allowlist: %s not in any allowlisted CIDR — access denied", client_ip_str)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Access denied: IP {client_ip_str} is not in the allowlist",
    )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_gate: PolicyGate | None = None


def get_policy_gate() -> PolicyGate:
    """Get the global PolicyGate instance."""
    global _gate
    if _gate is None:
        _gate = PolicyGate()
    return _gate
