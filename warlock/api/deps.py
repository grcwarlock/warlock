"""FastAPI dependencies for auth, DB sessions, and pagination."""

from __future__ import annotations

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
            if api_key and api_key.scopes:
                effective = role_perms & set(api_key.scopes)
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
