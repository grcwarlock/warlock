"""SSO/OIDC authentication flow for Warlock GRC.

Supports multiple OIDC providers: Okta, Azure AD, Google, and generic
OIDC-compliant identity providers. On successful authentication, issues
a local JWT and optionally auto-creates users on first login.

INT-1: SSO/OIDC integration.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from starlette.responses import RedirectResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/sso", tags=["sso"])

# OIDC discovery well-known path
_WELL_KNOWN = "/.well-known/openid-configuration"

# In-memory nonce/state store (short-lived, keyed by state param).
# GAP-077: This MUST be backed by Redis in production. In-memory storage
# breaks with multiple workers (each worker has its own dict, so a callback
# hitting a different worker than the login redirect will fail).
_pending_states: dict[str, dict[str, Any]] = {}
_STATE_TTL_SECONDS = 600  # 10 minutes


def _warn_sso_state_storage() -> None:
    """Log a warning at startup if SSO is enabled but no cache backend is configured."""
    settings = _get_settings()
    if settings.sso_enabled and not settings.cache_url:
        log.warning(
            "GAP-077: SSO is enabled but WLK_CACHE_URL is empty. "
            "SSO state is stored in-memory, which breaks with multiple workers. "
            "Configure WLK_CACHE_URL (Redis) for production SSO deployments."
        )


# ---------------------------------------------------------------------------
# Provider-specific discovery URLs
# ---------------------------------------------------------------------------

_PROVIDER_DISCOVERY: dict[str, str] = {
    "okta": "{issuer}/.well-known/openid-configuration",
    "azure_ad": "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    "google": "https://accounts.google.com/.well-known/openid-configuration",
    "generic_oidc": "{issuer}/.well-known/openid-configuration",
}


def _get_settings():
    """Lazy-load settings to avoid circular imports."""
    from warlock.config import get_settings

    return get_settings()


def _get_discovery_url(provider: str, issuer_url: str) -> str:
    """Build the OIDC discovery URL for a given provider."""
    if provider == "azure_ad":
        # Extract tenant from issuer URL: https://login.microsoftonline.com/{tenant}/v2.0
        parts = issuer_url.rstrip("/").split("/")
        tenant = "common"
        for i, part in enumerate(parts):
            if part == "login.microsoftonline.com" and i + 1 < len(parts):
                tenant = parts[i + 1]
                break
        return _PROVIDER_DISCOVERY["azure_ad"].format(tenant=tenant)

    if provider == "google":
        return _PROVIDER_DISCOVERY["google"]

    # Okta and generic: append well-known to issuer
    base = issuer_url.rstrip("/")
    return f"{base}{_WELL_KNOWN}"


def _fetch_json(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict:
    """Fetch JSON from a URL using stdlib urllib (no external deps required)."""
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        log.error("HTTP %d from %s: %s", exc.code, url, body)
        raise RuntimeError(f"OIDC HTTP error {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OIDC request failed: {exc}") from exc


def _discover_oidc(provider: str, issuer_url: str) -> dict:
    """Fetch OIDC discovery document and return parsed JSON."""
    url = _get_discovery_url(provider, issuer_url)
    log.info("Fetching OIDC discovery from %s", url)
    return _fetch_json(url)


def _generate_state() -> str:
    """Generate a cryptographically random state parameter."""
    return secrets.token_urlsafe(32)


def _generate_nonce() -> str:
    """Generate a cryptographically random nonce for ID token binding."""
    return secrets.token_urlsafe(32)


def _cleanup_expired_states() -> None:
    """Remove expired pending states to prevent memory leak."""
    now = time.time()
    expired = [k for k, v in _pending_states.items() if v.get("expires_at", 0) < now]
    for k in expired:
        del _pending_states[k]


def _decode_jwt_unverified(token: str) -> dict:
    """Decode a JWT payload without signature verification.

    This is used only for extracting claims from the ID token after we have
    already verified the token via the token endpoint (authorization code flow).
    The token endpoint response itself is trusted because it comes directly
    from the IdP over TLS.
    """
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    payload_b64 = parts[1]
    # Restore padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def _validate_id_token_claims(
    claims: dict, expected_nonce: str, client_id: str, issuer_url: str
) -> None:
    """Validate essential ID token claims per OIDC Core spec section 3.1.3.7."""
    # Issuer must match
    token_iss = claims.get("iss", "")
    if token_iss.rstrip("/") != issuer_url.rstrip("/"):
        raise ValueError(f"ID token issuer mismatch: expected {issuer_url}, got {token_iss}")

    # Audience must contain our client_id
    aud = claims.get("aud", "")
    if isinstance(aud, str):
        aud = [aud]
    if client_id not in aud:
        raise ValueError(f"ID token audience mismatch: {client_id} not in {aud}")

    # Nonce must match to prevent replay attacks
    if claims.get("nonce") != expected_nonce:
        raise ValueError("ID token nonce mismatch — possible replay attack")

    # Token must not be expired
    exp = claims.get("exp")
    if exp is not None and float(exp) < time.time():
        raise ValueError("ID token has expired")


def _extract_user_info(claims: dict, provider: str) -> dict[str, str]:
    """Extract normalized user info from ID token claims.

    Different providers use slightly different claim names.
    """
    email = claims.get("email", "")
    name = claims.get("name", "")
    subject = claims.get("sub", "")

    # Azure AD may use 'preferred_username' instead of 'email'
    if not email and provider == "azure_ad":
        email = claims.get("preferred_username", "")

    # Google uses 'email' directly (always present when email scope requested)

    if not email:
        raise ValueError("ID token missing email claim — ensure 'email' scope is requested")

    if not name:
        # Fallback: construct from given_name + family_name
        given = claims.get("given_name", "")
        family = claims.get("family_name", "")
        name = f"{given} {family}".strip() or email.split("@")[0]

    return {
        "email": email.lower().strip(),
        "name": name,
        "subject": subject,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


_sso_startup_warned = False


@router.get("/login")
async def sso_login(
    request: Request,
    redirect_uri: str | None = Query(None, description="Override callback URL"),
) -> RedirectResponse:
    """Initiate SSO login by redirecting to the OIDC provider.

    Generates a cryptographic state and nonce, stores them server-side,
    and redirects the user's browser to the provider's authorization endpoint.
    """
    global _sso_startup_warned
    if not _sso_startup_warned:
        _warn_sso_state_storage()
        _sso_startup_warned = True

    settings = _get_settings()

    if not settings.sso_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO is not enabled. Set WLK_SSO_ENABLED=true to enable.",
        )

    if not settings.sso_issuer_url or not settings.sso_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SSO misconfigured: missing issuer URL or client ID.",
        )

    provider = settings.sso_provider or "generic_oidc"

    # Fetch OIDC discovery document
    try:
        discovery = _discover_oidc(provider, settings.sso_issuer_url)
    except Exception as exc:
        log.error("OIDC discovery failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to reach identity provider. Check SSO configuration.",
        )

    authorization_endpoint = discovery.get("authorization_endpoint")
    if not authorization_endpoint:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="OIDC discovery missing authorization_endpoint.",
        )

    # Generate state and nonce
    state = _generate_state()
    nonce = _generate_nonce()

    # Determine callback URL
    callback_url = redirect_uri or settings.sso_callback_url
    if callback_url.startswith("/"):
        # Relative path — build absolute URL from request
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.url.netloc)
        callback_url = f"{scheme}://{host}{callback_url}"

    # Store state for validation on callback
    _cleanup_expired_states()
    _pending_states[state] = {
        "nonce": nonce,
        "provider": provider,
        "callback_url": callback_url,
        "expires_at": time.time() + _STATE_TTL_SECONDS,
    }

    # Build authorization URL
    params = {
        "client_id": settings.sso_client_id,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": callback_url,
        "state": state,
        "nonce": nonce,
    }

    # Provider-specific parameters
    if provider == "azure_ad":
        params["response_mode"] = "query"

    auth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    log.info("Redirecting to OIDC provider: %s (provider=%s)", authorization_endpoint, provider)

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback")
async def sso_callback(
    request: Request,
    code: str = Query(..., description="Authorization code from IdP"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
):
    """Handle OIDC callback after user authenticates with the identity provider.

    Exchanges the authorization code for tokens, validates the ID token,
    finds or creates the local user, and issues a Warlock JWT.
    """
    # Handle IdP-reported errors
    if error:
        log.warning("OIDC callback error: %s — %s", error, error_description)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Identity provider error: {error} — {error_description or 'no details'}",
        )

    settings = _get_settings()

    # Validate state parameter (CSRF protection)
    pending = _pending_states.pop(state, None)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter. Please restart the login flow.",
        )

    if pending.get("expires_at", 0) < time.time():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Login session expired. Please restart the login flow.",
        )

    provider = pending["provider"]
    nonce = pending["nonce"]
    callback_url = pending["callback_url"]

    # Fetch OIDC discovery to get token endpoint
    try:
        discovery = _discover_oidc(provider, settings.sso_issuer_url)
    except Exception as exc:
        log.error("OIDC discovery failed on callback: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to reach identity provider during token exchange.",
        )

    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="OIDC discovery missing token_endpoint.",
        )

    # Exchange authorization code for tokens
    token_data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": settings.sso_client_id,
            "client_secret": settings.sso_client_secret,
        }
    ).encode("utf-8")

    try:
        token_response = _fetch_json(token_endpoint, method="POST", data=token_data)
    except Exception as exc:
        log.error("Token exchange failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to exchange authorization code for tokens.",
        )

    id_token_raw = token_response.get("id_token")
    if not id_token_raw:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Token response missing id_token.",
        )

    # Decode and validate ID token claims
    try:
        claims = _decode_jwt_unverified(id_token_raw)
        _validate_id_token_claims(claims, nonce, settings.sso_client_id, settings.sso_issuer_url)
    except ValueError as exc:
        log.error("ID token validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"ID token validation failed: {exc}",
        )

    # Extract user info from claims
    try:
        user_info = _extract_user_info(claims, provider)
    except ValueError as exc:
        log.error("User info extraction failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    # Find or create local user
    from warlock.api.auth import create_access_token, generate_refresh_token
    from warlock.db.engine import get_session
    from warlock.db.models import User

    with get_session() as db:
        # Look up by SSO subject first (most reliable), then by email
        user = (
            db.query(User)
            .filter(
                User.sso_provider == provider,
                User.sso_subject_id == user_info["subject"],
            )
            .first()
        )

        if not user:
            # Try matching by email (link existing account)
            user = db.query(User).filter(User.email == user_info["email"]).first()

        if user:
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is deactivated. Contact your administrator.",
                )
            # Update SSO fields on existing user
            user.sso_provider = provider
            user.sso_subject_id = user_info["subject"]
            user.last_login = datetime.now(timezone.utc)
            user.name = user_info["name"]  # Keep name in sync with IdP
            log.info("SSO login for existing user: %s (provider=%s)", user.email, provider)
        elif settings.sso_auto_create_users:
            # Auto-create user on first SSO login
            user = User(
                email=user_info["email"],
                name=user_info["name"],
                hashed_password="sso:no-password",  # SSO users do not have local passwords
                role=settings.sso_default_role,
                is_active=True,
                sso_provider=provider,
                sso_subject_id=user_info["subject"],
                last_login=datetime.now(timezone.utc),
            )
            db.add(user)
            db.flush()
            log.info(
                "Auto-created SSO user: %s (provider=%s, role=%s)",
                user.email,
                provider,
                settings.sso_default_role,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No matching account found and auto-creation is disabled.",
            )

        # Issue Warlock JWT tokens
        access_token = create_access_token({"sub": user.id})
        refresh_token = generate_refresh_token(user.id, db)

        log.info("SSO authentication complete for user %s", user.email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "sso_provider": provider,
            },
        }
