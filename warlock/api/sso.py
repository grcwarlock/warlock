"""SSO/OIDC authentication flow for Warlock GRC.

Supports multiple OIDC providers: Okta, Azure AD, Google, and generic
OIDC-compliant identity providers. On successful authentication, issues
a local JWT and optionally auto-creates users on first login.

INT-1: SSO/OIDC integration. GAP-077: shared cache for OAuth state.
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

# OAuth state is stored via ``warlock.utils.cache`` (Redis when WLK_CACHE_URL is set).
# GAP-077: Production + SSO requires Redis so callbacks hit shared state across workers.
_STATE_TTL_SECONDS = 600  # 10 minutes
_SSO_STATE_KEY_PREFIX = "sso_state:"


def _get_cache():
    from warlock.utils.cache import get_cache

    return get_cache()


def _store_sso_state(state: str, data: dict[str, Any]) -> None:
    cache = _get_cache()
    cache.set(f"{_SSO_STATE_KEY_PREFIX}{state}", data, ttl=_STATE_TTL_SECONDS)


def _pop_sso_state(state: str) -> dict[str, Any] | None:
    cache = _get_cache()
    key = f"{_SSO_STATE_KEY_PREFIX}{state}"
    pending = cache.get(key)
    cache.delete(key)
    return pending


def _warn_sso_state_storage() -> None:
    """Log a warning at startup if SSO is enabled but no cache backend is configured."""
    settings = _get_settings()
    if settings.sso_enabled and not settings.cache_url:
        log.warning(
            "GAP-077: SSO is enabled but WLK_CACHE_URL is empty. "
            "SSO state uses in-memory cache only — breaks with multiple workers. "
            "Configure WLK_CACHE_URL (Redis) for production. "
            "Production env refuses to start without Redis when SSO is on."
        )


def _resolve_sso_role(claims: dict[str, Any], settings: Any) -> str:
    """Map IdP groups/roles claim to a Warlock role using WLK_SSO_ROLE_MAPPING."""
    from warlock.api.auth import PERMISSIONS

    default = settings.sso_default_role
    mapping: dict[str, str] = {}
    raw_map = getattr(settings, "sso_role_mapping", None) or "{}"
    # F18: bound the input size before json.loads to defuse a JSON-bomb /
    # memory-exhaustion vector via misconfigured env var.
    _MAX_ROLE_MAPPING_BYTES = 16 * 1024  # 16 KiB
    if isinstance(raw_map, str) and raw_map.strip():
        if len(raw_map) > _MAX_ROLE_MAPPING_BYTES:
            log.error(
                "WLK_SSO_ROLE_MAPPING exceeds %d bytes (got %d) — refusing to parse",
                _MAX_ROLE_MAPPING_BYTES,
                len(raw_map),
            )
            return default if default in PERMISSIONS else "viewer"
        try:
            mapping = json.loads(raw_map)
        except json.JSONDecodeError:
            log.warning("Invalid WLK_SSO_ROLE_MAPPING JSON — using default role %s", default)
            return default if default in PERMISSIONS else "viewer"
        # Defensive: ensure parsed result is a flat dict[str, str] under a sane size
        if not isinstance(mapping, dict) or len(mapping) > 256:
            log.error(
                "WLK_SSO_ROLE_MAPPING must parse to a dict of <=256 entries; got %s",
                type(mapping).__name__,
            )
            return default if default in PERMISSIONS else "viewer"
        mapping = {
            str(k)[:200]: str(v)[:50]
            for k, v in mapping.items()
            if isinstance(k, str) and isinstance(v, str)
        }
    if not mapping:
        return default if default in PERMISSIONS else "viewer"

    claim_name = (getattr(settings, "sso_groups_claim", None) or "").strip()
    if not claim_name:
        return default if default in PERMISSIONS else "viewer"

    raw = claims.get(claim_name)
    groups: list[str] = []
    if isinstance(raw, str):
        groups = [raw]
    elif isinstance(raw, list):
        groups = [str(x) for x in raw]

    for g in groups:
        if g in mapping:
            role = mapping[g]
            if role in PERMISSIONS:
                return role
            log.warning("SSO role mapping references unknown role %r for group %s", role, g)

    return default if default in PERMISSIONS else "viewer"


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


def _decode_jwt_unverified(token: str) -> dict:
    """Decode a JWT payload without signature verification.

    Retained only for legacy/fallback paths. New callers MUST use
    ``_decode_and_verify_id_token`` which enforces RS256/ES256 signature
    verification against the IdP's JWKS (finding F8).
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


# ---------------------------------------------------------------------------
# JWKS cache — simple TTL cache keyed by jwks_uri (F8)
# ---------------------------------------------------------------------------

_JWKS_CACHE: dict[str, tuple[float, dict]] = {}
_JWKS_TTL_SECONDS = 3600  # 1h


def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch and cache the JWKS document for a given JWKS URI."""
    now = time.time()
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached and (now - cached[0]) < _JWKS_TTL_SECONDS:
        return cached[1]
    jwks = _fetch_json(jwks_uri)
    _JWKS_CACHE[jwks_uri] = (now, jwks)
    return jwks


def _decode_and_verify_id_token(
    id_token: str,
    discovery: dict,
    client_id: str,
    issuer_url: str,
) -> dict:
    """Verify ID token signature using the IdP's JWKS, then return claims.

    Requires PyJWT. Raises ValueError on any failure (missing key, bad
    signature, unsupported alg, etc.). Callers catch ValueError and map to
    401.
    """
    try:
        import jwt as _pyjwt  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError(
            "PyJWT is required to verify SSO ID tokens. Install with: pip install pyjwt"
        ) from exc

    jwks_uri = discovery.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("OIDC discovery document missing jwks_uri")

    # Use PyJWT's JWKS client if available (handles key rotation and caching too)
    try:
        jwk_client = _pyjwt.PyJWKClient(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token).key
    except Exception as exc:
        # Fallback: fetch JWKS ourselves and match by kid
        try:
            header = _pyjwt.get_unverified_header(id_token)
            kid = header.get("kid")
            jwks = _fetch_jwks(jwks_uri)
            matched = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
            if matched is None:
                raise ValueError(f"JWKS has no key matching kid={kid}") from exc
            signing_key = _pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(matched))
        except Exception as inner:
            raise ValueError(f"Could not resolve signing key: {inner}") from inner

    # Accept signing algorithms advertised by the IdP, defaulting to RS256/ES256
    id_token_algs = discovery.get("id_token_signing_alg_values_supported") or [
        "RS256",
        "ES256",
    ]
    try:
        claims = _pyjwt.decode(
            id_token,
            signing_key,
            algorithms=id_token_algs,
            audience=client_id,
            issuer=issuer_url.rstrip("/"),
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except Exception as exc:
        raise ValueError(f"ID token signature/claims verification failed: {exc}") from exc

    return claims


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

    # Store state for validation on callback (Redis or in-memory)
    _store_sso_state(
        state,
        {
            "nonce": nonce,
            "provider": provider,
            "callback_url": callback_url,
        },
    )

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
    pending = _pop_sso_state(state)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter. Please restart the login flow.",
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

    # Verify ID token signature (F8) and validate claims
    try:
        claims = _decode_and_verify_id_token(
            id_token_raw,
            discovery,
            settings.sso_client_id,
            settings.sso_issuer_url,
        )
        # PyJWT checks iss/aud/exp; we still need nonce check for replay protection
        if claims.get("nonce") != nonce:
            raise ValueError("ID token nonce mismatch — possible replay attack")
    except ValueError as exc:
        log.error("ID token verification failed: %s", exc)
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

    resolved_role = _resolve_sso_role(claims, settings)

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
            if getattr(settings, "sso_groups_claim", None) or (
                getattr(settings, "sso_role_mapping", "{}") or "{}"
            ).strip() not in ("", "{}"):
                user.role = resolved_role
            log.info("SSO login for existing user: %s (provider=%s)", user.email, provider)
        elif settings.sso_auto_create_users:
            # Auto-create user on first SSO login
            user = User(
                email=user_info["email"],
                name=user_info["name"],
                hashed_password="sso:no-password",  # SSO users do not have local passwords
                role=resolved_role,
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
                resolved_role,
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
