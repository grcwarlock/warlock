"""SCIM 2.0 user provisioning endpoints for Warlock GRC.

Implements the System for Cross-domain Identity Management (SCIM) 2.0
protocol (RFC 7643/7644) for automated user lifecycle management from
identity providers like Okta, Azure AD, and OneLogin.

INT-2: SCIM provisioning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from warlock.api.deps import get_db
from warlock.db.models import User
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scim", tags=["scim"])

# SCIM schema URIs
_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

# SCIM content type
_SCIM_CONTENT_TYPE = "application/scim+json"


# ---------------------------------------------------------------------------
# SCIM Bearer Token Authentication
# ---------------------------------------------------------------------------


def _get_scim_token() -> str:
    """Load the SCIM bearer token from settings.

    The SCIM token is separate from user JWT tokens. It authenticates
    the identity provider's SCIM client, not individual users.
    """
    from warlock.config import get_settings

    settings = get_settings()
    token = getattr(settings, "scim_bearer_token", "") or ""
    if not token:
        # Fall back to a setting derived from the JWT secret for dev convenience
        log.warning(
            "WLK_SCIM_BEARER_TOKEN not set. SCIM endpoints are unprotected. Set this in production."
        )
    return token


def _verify_scim_auth(authorization: str | None = Header(None)) -> None:
    """Verify SCIM bearer token authentication.

    Raises 401 if the token is missing or invalid. Uses constant-time
    comparison to prevent timing attacks on the bearer token.
    """
    expected = _get_scim_token()
    if not expected:
        # No token configured — allow in dev, but log warning
        return

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SCIM authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme — use Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]
    import hmac as _hmac

    if not _hmac.compare_digest(token, expected):
        log.warning("SCIM authentication failed: invalid bearer token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# SCIM Resource Serialization
# ---------------------------------------------------------------------------


def _user_to_scim(user: User, base_url: str) -> dict[str, Any]:
    """Convert a Warlock User model to a SCIM 2.0 User resource."""
    created_at = ensure_aware(user.created_at) if user.created_at else None
    last_login = ensure_aware(user.last_login) if user.last_login else None

    # Split name into components (best-effort)
    name_parts = (user.name or "").split(" ", 1)
    given_name = name_parts[0] if name_parts else ""
    family_name = name_parts[1] if len(name_parts) > 1 else ""

    resource: dict[str, Any] = {
        "schemas": [_USER_SCHEMA],
        "id": user.id,
        "externalId": user.sso_subject_id or user.id,
        "userName": user.email,
        "name": {
            "givenName": given_name,
            "familyName": family_name,
            "formatted": user.name or "",
        },
        "emails": [
            {
                "value": user.email,
                "type": "work",
                "primary": True,
            }
        ],
        "displayName": user.name or user.email,
        "active": user.is_active,
        "roles": [
            {
                "value": user.role,
                "display": user.role,
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "User",
            "location": f"{base_url}/api/v1/scim/Users/{user.id}",
            "created": created_at.isoformat() if created_at else None,
            "lastModified": (last_login or created_at or datetime.now(timezone.utc)).isoformat(),
        },
    }
    return resource


def _scim_error(status_code: int, detail: str) -> dict[str, Any]:
    """Build a SCIM 2.0 error response body."""
    return {
        "schemas": [_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }


def _get_base_url(request: Request) -> str:
    """Extract the base URL from the request for SCIM resource locations."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}"


# ---------------------------------------------------------------------------
# SCIM Endpoints
# ---------------------------------------------------------------------------


@router.get("/Users")
async def list_users(
    request: Request,
    startIndex: int = Query(1, ge=1, alias="startIndex"),
    count: int = Query(100, ge=1, le=1000, alias="count"),
    filter: str | None = Query(None, alias="filter"),
    db: Session = Depends(get_db),
    _auth: None = Depends(_verify_scim_auth),
):
    """List users in SCIM 2.0 format.

    Supports basic filtering on userName (email) as required by most
    IdP SCIM clients: ``filter=userName eq "user@example.com"``
    """
    base_url = _get_base_url(request)
    query = db.query(User)

    # Parse basic SCIM filter (IdPs typically only use userName eq "...")
    if filter:
        filter_lower = filter.strip()
        if filter_lower.lower().startswith("username eq "):
            # Extract the email value
            parts = filter_lower.split('"')
            if len(parts) >= 2:
                email_filter = parts[1].lower().strip()
                query = query.filter(User.email == email_filter)
            else:
                log.warning("SCIM filter parse failed: %s", filter)
        elif filter_lower.lower().startswith("externalid eq "):
            parts = filter_lower.split('"')
            if len(parts) >= 2:
                ext_id = parts[1].strip()
                query = query.filter(User.sso_subject_id == ext_id)
        else:
            log.warning("Unsupported SCIM filter: %s (ignored)", filter)

    total = query.count()
    # SCIM uses 1-based indexing
    users = query.offset(startIndex - 1).limit(count).all()

    return {
        "schemas": [_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(users),
        "Resources": [_user_to_scim(u, base_url) for u in users],
    }


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    db: Session = Depends(get_db),
    _auth: None = Depends(_verify_scim_auth),
):
    """Create a user via SCIM 2.0 provisioning.

    The identity provider sends user attributes; we create a local account
    with SSO linkage and no local password.
    """
    body = await request.json()
    base_url = _get_base_url(request)

    # Extract required fields
    username = body.get("userName", "").lower().strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="userName is required",
        )

    # Check for existing user
    existing = db.query(User).filter(User.email == username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email {username} already exists",
        )

    # Extract name components
    name_obj = body.get("name", {})
    given_name = name_obj.get("givenName", "")
    family_name = name_obj.get("familyName", "")
    display_name = body.get("displayName", "")
    full_name = display_name or f"{given_name} {family_name}".strip() or username.split("@")[0]

    # Extract external ID
    external_id = body.get("externalId", "")

    # Determine role from SCIM roles array (default to configured SSO role)
    from warlock.config import get_settings

    settings = get_settings()
    role = settings.sso_default_role
    scim_roles = body.get("roles", [])
    if scim_roles and isinstance(scim_roles, list):
        first_role = scim_roles[0].get("value", "")
        from warlock.api.auth import PERMISSIONS

        if first_role in PERMISSIONS:
            role = first_role

    # Determine active status
    is_active = body.get("active", True)

    user = User(
        email=username,
        name=full_name,
        hashed_password="scim:no-password",  # SCIM-provisioned users authenticate via SSO
        role=role,
        is_active=is_active,
        sso_subject_id=external_id,
    )
    db.add(user)
    db.flush()

    log.info("SCIM user created: %s (external_id=%s, role=%s)", username, external_id, role)
    return _user_to_scim(user, base_url)


@router.get("/Users/{user_id}")
async def get_user(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
    _auth: None = Depends(_verify_scim_auth),
):
    """Get a single user by ID in SCIM 2.0 format."""
    base_url = _get_base_url(request)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    return _user_to_scim(user, base_url)


@router.put("/Users/{user_id}")
async def update_user(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
    _auth: None = Depends(_verify_scim_auth),
):
    """Update a user via SCIM 2.0 (full replacement).

    IdPs use PUT for full user replacement. We update name, email,
    active status, and external ID.
    """
    body = await request.json()
    base_url = _get_base_url(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Update userName (email)
    new_email = body.get("userName", "").lower().strip()
    if new_email and new_email != user.email:
        # Check for email conflict
        conflict = db.query(User).filter(User.email == new_email, User.id != user_id).first()
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email {new_email} is already in use",
            )
        user.email = new_email

    # Update name
    name_obj = body.get("name", {})
    given_name = name_obj.get("givenName", "")
    family_name = name_obj.get("familyName", "")
    display_name = body.get("displayName", "")
    full_name = display_name or f"{given_name} {family_name}".strip()
    if full_name:
        user.name = full_name

    # Update active status (SCIM deactivation)
    if "active" in body:
        user.is_active = bool(body["active"])
        if not user.is_active:
            log.info("SCIM deactivated user: %s", user.email)

    # Update external ID
    external_id = body.get("externalId", "")
    if external_id:
        user.sso_subject_id = external_id

    # Update role if provided
    scim_roles = body.get("roles", [])
    if scim_roles and isinstance(scim_roles, list):
        first_role = scim_roles[0].get("value", "")
        from warlock.api.auth import PERMISSIONS

        if first_role in PERMISSIONS:
            user.role = first_role

    db.flush()
    log.info("SCIM user updated: %s (id=%s)", user.email, user_id)
    return _user_to_scim(user, base_url)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    _auth: None = Depends(_verify_scim_auth),
):
    """Deactivate a user via SCIM 2.0 DELETE.

    Per SCIM best practices, we soft-delete (deactivate) rather than
    hard-delete to preserve audit trail integrity. The hash-chained
    audit log references user IDs, so hard deletion would break the chain.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    user.is_active = False
    # Invalidate any existing tokens by setting token_valid_after to now
    user.token_valid_after = datetime.now(timezone.utc)
    db.flush()

    log.info("SCIM user deactivated: %s (id=%s)", user.email, user_id)
    return None
