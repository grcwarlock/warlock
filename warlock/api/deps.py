"""FastAPI dependencies for auth, DB sessions, and pagination."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from warlock.db.engine import get_session as _get_session
from warlock.db.models import User
from warlock.api.auth import (
    authenticate_api_key,
    decode_access_token,
    has_permission,
    PERMISSIONS,
)

log = logging.getLogger(__name__)


def get_db():
    """Yield a database session."""
    with _get_session() as session:
        yield session


@dataclass
class AuthContext:
    """Authenticated user context with effective permissions.

    When authenticated via API key, effective_permissions is the intersection
    of the user's role permissions and the API key's scopes — so a read-only
    API key on an admin user only gets read access. (C-3 fix)
    """
    user: User
    effective_permissions: set[str] = field(default_factory=set)
    via_api_key: bool = False
    api_key_id: str | None = None


def get_current_user(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Extract and validate the current user from auth headers.

    Returns an AuthContext with effective permissions scoped by API key
    when using key-based auth.
    """
    # Try API key first
    if x_api_key:
        user, api_key = authenticate_api_key(db, x_api_key)
        if user:
            role_perms = PERMISSIONS.get(user.role, set())
            # Intersect with API key scopes if scopes are defined
            if api_key:
                if api_key.scopes:  # Non-empty scopes: intersect with role
                    effective = role_perms & set(api_key.scopes)
                else:  # Empty scopes list: no permissions (not full permissions)
                    effective = set()
                    log.warning("API key %s has empty scopes — no permissions granted", api_key.id[:8])
            else:
                effective = role_perms
            return AuthContext(
                user=user,
                effective_permissions=effective,
                via_api_key=True,
                api_key_id=api_key.id if api_key else None,
            )

    # Try JWT bearer token
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            payload = decode_access_token(token)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject",
            )
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        # Token revocation check
        if user.token_valid_after:
            token_iat = payload.get("iat", 0)
            valid_after = user.token_valid_after
            if valid_after.tzinfo is None:
                valid_after = valid_after.replace(tzinfo=__import__("datetime").timezone.utc)
            if token_iat < valid_after.timestamp():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                )
        return AuthContext(
            user=user,
            effective_permissions=PERMISSIONS.get(user.role, set()),
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


def require_permission(permission: str):
    """Dependency factory that checks user has a specific permission.

    Checks effective_permissions which accounts for API key scope restrictions.
    """

    def checker(ctx: AuthContext = Depends(get_current_user)):
        if permission not in ctx.effective_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )
        return ctx.user

    return checker


def apply_framework_scope(query, model_class, user: User):
    """Apply user's allowed_frameworks filter to a query.

    If user.allowed_frameworks is empty, no filter is applied (access to all).
    Otherwise, filters to only the allowed frameworks.
    """
    if user.allowed_frameworks:
        query = query.filter(model_class.framework.in_(user.allowed_frameworks))
    return query


def apply_source_scope(query, model_class, user: User):
    """Apply user's allowed_sources filter to a query."""
    if user.allowed_sources:
        if hasattr(model_class, 'source'):
            query = query.filter(model_class.source.in_(user.allowed_sources))
        elif hasattr(model_class, 'provider'):
            query = query.filter(model_class.provider.in_(user.allowed_sources))
    return query
