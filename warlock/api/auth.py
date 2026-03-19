"""Authentication and role-based access control.

Supports two auth methods:
1. JWT bearer tokens (for UI/browser sessions)
2. API key header (for programmatic access)

Roles:
- admin: full access, manage users/keys
- auditor: read-only across all frameworks
- owner: read/write for their scoped frameworks/sources
- viewer: read-only for their scoped frameworks/sources
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import User, APIKey

log = logging.getLogger(__name__)

# Configuration — loaded from Settings, not raw os.environ
def _load_auth_config():
    from warlock.config import get_settings
    s = get_settings()
    return s.jwt_secret, s.jwt_expire_minutes

ALGORITHM = "HS256"

# Lazy-loaded from settings on first use
_SECRET_KEY: str | None = None
_EXPIRE_MINUTES: int | None = None

def _get_auth_config() -> tuple[str, int]:
    global _SECRET_KEY, _EXPIRE_MINUTES
    if _SECRET_KEY is None:
        _SECRET_KEY, _EXPIRE_MINUTES = _load_auth_config()
    return _SECRET_KEY, _EXPIRE_MINUTES

# Minimum password length
MIN_PASSWORD_LENGTH = 12

# Detect PyJWT availability
try:
    import jwt as _pyjwt

    _HAS_PYJWT = True
except ImportError:
    _pyjwt = None  # type: ignore[assignment]
    _HAS_PYJWT = False

# Detect bcrypt availability — preferred for password hashing
try:
    import bcrypt as _bcrypt

    _HAS_BCRYPT = True
except ImportError:
    _bcrypt = None  # type: ignore[assignment]
    _HAS_BCRYPT = False


# ---------------------------------------------------------------------------
# Password hashing — bcrypt preferred, PBKDF2 fallback (C-1 fix)
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (preferred) or PBKDF2-SHA256 fallback.

    Never uses plain SHA-256. Both bcrypt and PBKDF2 are memory-hard or
    iteration-hard to resist GPU brute-force attacks.
    """
    if _HAS_BCRYPT:
        hashed = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12))
        return f"bcrypt:{hashed.decode()}"
    # Fallback: PBKDF2 with 600k iterations (OWASP 2024 recommendation)
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600_000)
    return f"pbkdf2:{salt}:{dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash. Supports bcrypt, pbkdf2, and legacy sha256."""
    if hashed.startswith("bcrypt:"):
        if not _HAS_BCRYPT:
            log.error("bcrypt hash found but bcrypt not installed")
            return False
        stored = hashed[7:].encode()
        return _bcrypt.checkpw(password.encode(), stored)
    elif hashed.startswith("pbkdf2:"):
        _, salt, expected_hex = hashed.split(":", 2)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600_000)
        return hmac.compare_digest(dk.hex(), expected_hex)
    else:
        # Legacy SHA-256 format — verify but log warning for migration
        salt, expected = hashed.split(":", 1)
        actual = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        if hmac.compare_digest(actual, expected):
            log.warning("User authenticated with legacy SHA-256 hash — should be migrated")
            return True
        return False


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------


def _hmac_encode(payload: dict, secret: str) -> str:
    """Simple HMAC-based token when PyJWT is not installed."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).rstrip(b"=")
    signing_input = header + b"." + body
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + signature).decode()


def _hmac_decode(token: str, secret: str) -> dict:
    """Decode and verify an HMAC-based token."""
    parts = token.encode().split(b".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    signing_input = parts[0] + b"." + parts[1]
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    # Restore padding for base64 decode
    sig_b64 = parts[2]
    sig_b64 += b"=" * (4 - len(sig_b64) % 4) if len(sig_b64) % 4 else b""
    actual_sig = base64.urlsafe_b64decode(sig_b64)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid token signature")
    body_b64 = parts[1]
    body_b64 += b"=" * (4 - len(body_b64) % 4) if len(body_b64) % 4 else b""
    payload = json.loads(base64.urlsafe_b64decode(body_b64))
    return payload


def _get_jwt_secret() -> str:
    """Get JWT secret, refusing to use a hardcoded fallback in production."""
    secret, _ = _get_auth_config()
    if not secret:
        # Dev mode: generate an ephemeral secret and warn loudly
        log.warning(
            "WLK_JWT_SECRET not set — using ephemeral secret. "
            "Tokens will not survive restarts. Set WLK_JWT_SECRET for production."
        )
        global _EPHEMERAL_SECRET
        if not _EPHEMERAL_SECRET:
            _EPHEMERAL_SECRET = secrets.token_urlsafe(48)
        return _EPHEMERAL_SECRET
    return secret

_EPHEMERAL_SECRET: str = ""


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    secret = _get_jwt_secret()
    _, expire_minutes = _get_auth_config()
    to_encode = {"sub": data.get("sub", "")}  # Only include sub claim (M-3 fix)
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=expire_minutes))
    to_encode["exp"] = expire.timestamp()
    to_encode["iat"] = datetime.now(timezone.utc).timestamp()

    if _HAS_PYJWT:
        return _pyjwt.encode(to_encode, secret, algorithm=ALGORITHM)
    return _hmac_encode(to_encode, secret)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token. Raises ValueError on failure."""
    secret = _get_jwt_secret()
    try:
        if _HAS_PYJWT:
            payload = _pyjwt.decode(token, secret, algorithms=[ALGORITHM])
        else:
            payload = _hmac_decode(token, secret)
    except Exception as exc:
        raise ValueError(f"Invalid token: {exc}") from exc

    # Check expiration
    exp = payload.get("exp")
    if exp is not None and float(exp) < datetime.now(timezone.utc).timestamp():
        raise ValueError("Token has expired")
    return payload


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def generate_api_key() -> tuple[str, str]:
    """Generate an API key. Returns (raw_key, key_hash)."""
    raw_key = f"wlk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, key_hash


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def validate_password(password: str) -> list[str]:
    """Validate password complexity. Returns list of issues (empty = valid)."""
    issues = []
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    return issues


def validate_role(role: str) -> bool:
    """Validate role is a known value."""
    return role in PERMISSIONS


def create_user(session: Session, email: str, name: str, password: str, role: str = "viewer") -> User:
    """Create a new user with password validation and role validation."""
    if not validate_role(role):
        raise ValueError(f"Invalid role: {role!r}. Must be one of: {', '.join(PERMISSIONS.keys())}")
    pw_issues = validate_password(password)
    if pw_issues:
        raise ValueError(f"Password validation failed: {'; '.join(pw_issues)}")
    user = User(
        email=email,
        name=name,
        hashed_password=hash_password(password),
        role=role,
    )
    session.add(user)
    session.flush()
    return user


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    """Authenticate a user by email and password."""
    user = session.query(User).filter(User.email == email, User.is_active == True).first()  # noqa: E712
    if user and verify_password(password, user.hashed_password):
        user.last_login = datetime.now(timezone.utc)
        return user
    return None


def authenticate_api_key(session: Session, raw_key: str) -> tuple[User | None, APIKey | None]:
    """Authenticate by API key."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = session.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True,  # noqa: E712
    ).first()
    if not api_key:
        return None, None
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        return None, None
    user = session.query(User).filter(User.id == api_key.user_id).first()
    api_key.last_used = datetime.now(timezone.utc)
    return user, api_key


# ---------------------------------------------------------------------------
# Role permission matrix
# ---------------------------------------------------------------------------

PERMISSIONS: dict[str, set[str]] = {
    "admin": {"read", "write", "delete", "manage_users", "manage_keys", "run_pipeline", "export"},
    "auditor": {"read", "export"},
    "owner": {"read", "write", "run_pipeline", "export"},
    "viewer": {"read"},
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in PERMISSIONS.get(role, set())
