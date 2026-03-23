"""Authentication routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.auth import (
    create_access_token,
    create_user,
    generate_api_key,
    login_with_tokens,
    rotate_refresh_token,
    verify_mfa_login,
    PERMISSIONS,
)
from warlock.api.deps import get_db, require_permission
from warlock.api.routers.schemas import MessageResponse, _dt_str
from warlock.db.models import APIKey, User
from warlock.db.repository import get_repos

router = APIRouter()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    role: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str = "viewer"


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    allowed_frameworks: list[str]
    allowed_sources: list[str]
    created_at: str
    last_login: str | None

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    allowed_frameworks: list[str] | None = None
    allowed_sources: list[str] | None = None


class APIKeyCreateRequest(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=list)
    expires_days: int | None = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    scopes: list[str]
    is_active: bool
    created_at: str
    last_used: str | None
    raw_key: str | None = None  # only returned on creation

    model_config = {"from_attributes": True}


class MFAVerifyRequest(BaseModel):
    mfa_token: str  # Signed challenge token from login response
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_to_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        is_active=user.is_active,
        allowed_frameworks=user.allowed_frameworks or [],
        allowed_sources=user.allowed_sources or [],
        created_at=_dt_str(user.created_at) or "",
        last_login=_dt_str(user.last_login),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    result = login_with_tokens(db, body.email, body.password)
    if result is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # MFA required — return signed challenge token, not raw user_id
    if isinstance(result, dict) and result.get("mfa_required"):
        return {
            "mfa_required": True,
            "mfa_token": result["mfa_token"],
            "message": "MFA verification required. POST to /auth/mfa/verify with mfa_token and code.",
        }
    # Full auth — return access + refresh tokens (#3 refresh tokens wired in)
    return result


@router.post("/auth/mfa/verify")
def mfa_verify(body: MFAVerifyRequest, db: Session = Depends(get_db)):
    """Complete MFA login by verifying TOTP code. Issues tokens on success."""
    from warlock.api.auth import verify_mfa_challenge, generate_refresh_token

    # Verify the signed challenge token (replaces raw user_id)
    user_id = verify_mfa_challenge(body.mfa_token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge token",
        )
    if not verify_mfa_login(user_id, body.code, db):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
    # MFA verified — issue tokens
    repos = get_repos(db)
    user = repos.users.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    access_token = create_access_token({"sub": user.id})
    refresh_token = generate_refresh_token(user.id, db)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


@router.post("/auth/refresh")
def refresh_token_endpoint(body: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a refresh token for a new access + refresh token pair."""
    try:
        new_access, new_refresh = rotate_refresh_token(body.refresh_token, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": 3600,
    }


@router.post("/auth/register", response_model=UserResponse, status_code=201)
def register(
    body: RegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    # Check if email already exists
    repos = get_repos(db)
    existing = repos.users.by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = create_user(db, body.email, body.name, body.password, body.role)
    return _user_to_response(user)


@router.post("/auth/api-keys", response_model=APIKeyResponse, status_code=201)
def create_api_key_endpoint(
    body: APIKeyCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    # S-11: Validate all requested scopes are valid permission names
    if body.scopes:
        all_valid_perms = set()
        for perms in PERMISSIONS.values():
            all_valid_perms.update(perms)
        invalid_scopes = set(body.scopes) - all_valid_perms
        if invalid_scopes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scopes: {sorted(invalid_scopes)}. Valid scopes: {sorted(all_valid_perms)}",
            )

    raw_key, key_hash = generate_api_key()
    expires_at = None
    if body.expires_days:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    api_key = APIKey(
        user_id=current_user.id,
        key_hash=key_hash,
        name=body.name,
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.flush()

    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        scopes=api_key.scopes or [],
        is_active=True,
        created_at=_dt_str(api_key.created_at) or "",
        last_used=None,
        raw_key=raw_key,
    )


@router.get("/auth/api-keys", response_model=list[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).all()
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            scopes=k.scopes or [],
            is_active=k.is_active,
            created_at=_dt_str(k.created_at) or "",
            last_used=_dt_str(k.last_used),
        )
        for k in keys
    ]


@router.delete("/auth/api-keys/{key_id}", response_model=MessageResponse)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    api_key = (
        db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.is_active = False
    return MessageResponse(message="API key revoked")


@router.post("/auth/logout")
def logout(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Revoke all tokens for the current user."""
    from datetime import datetime, timezone

    current_user.token_valid_after = datetime.now(timezone.utc)
    db.flush()
    return {"message": "All tokens revoked"}
