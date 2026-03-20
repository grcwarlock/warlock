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
import secrets
import struct
import time
from datetime import datetime, timezone, timedelta

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
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 30
_PBKDF2_ITERATIONS = 600_000

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
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
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
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), expected_hex)
    else:
        # Legacy SHA-256 format — verify but log warning for migration
        # S-14: Migration path: legacy hashes are auto-upgraded on next login
        # in authenticate_user(). This path should be fully deprecated.
        salt, expected = hashed.split(":", 1)
        actual = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        if hmac.compare_digest(actual, expected):
            log.warning(
                "User authenticated with legacy SHA-256 hash — must be migrated. "
                "Hash will be auto-upgraded on next successful login via authenticate_user()."
            )
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


def _is_dev_env() -> bool:
    """Return True if running in development mode (S-3 helper)."""
    import os
    env = os.environ.get("WLK_ENV", "").strip().lower()
    return env in ("", "development")


def _get_jwt_secret() -> str:
    """Get JWT secret, refusing to start without one in production.

    S-3: Enforce minimum 32-character JWT secret in non-development environments.
    """
    secret, _ = _get_auth_config()
    if not secret:
        from warlock.config import get_settings
        settings = get_settings()
        if settings.env == "production":
            raise RuntimeError(
                "CRITICAL: WLK_JWT_SECRET is not set. "
                "Refusing to start in production without a JWT secret. "
                "Set WLK_JWT_SECRET to a random string of at least 32 characters."
            )
        log.critical(
            "WLK_JWT_SECRET not set — using ephemeral secret. "
            "Tokens will NOT survive restarts. This is ONLY acceptable in development."
        )
        global _EPHEMERAL_SECRET
        if not _EPHEMERAL_SECRET:
            _EPHEMERAL_SECRET = secrets.token_urlsafe(48)
        return _EPHEMERAL_SECRET
    # S-3: Reject short secrets in non-development environments
    if len(secret) < 32:
        if not _is_dev_env():
            raise RuntimeError(
                f"CRITICAL: WLK_JWT_SECRET is only {len(secret)} characters. "
                "A minimum of 32 characters is required in non-development environments. "
                "Set WLK_JWT_SECRET to a random string of at least 32 characters."
            )
        log.warning("WLK_JWT_SECRET is shorter than 32 characters — this is insecure for production")
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

    # S-15: Reject tokens without an exp claim
    exp = payload.get("exp")
    if exp is None:
        raise ValueError("Token missing exp claim")
    if float(exp) < datetime.now(timezone.utc).timestamp():
        raise ValueError("Token has expired")
    return payload


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def _hmac_key_hash(raw_key: str) -> str:
    """Compute HMAC-SHA256 of an API key using the JWT secret as HMAC key.

    S-5: Uses HMAC instead of plain SHA-256 to prevent offline brute-force
    if the database is compromised without the server secret.
    """
    server_secret, _ = _get_auth_config()
    return hmac.new(server_secret.encode(), raw_key.encode(), hashlib.sha256).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Generate an API key. Returns (raw_key, key_hash).

    S-5: Uses HMAC-SHA256 with the JWT secret as HMAC key.
    """
    raw_key = f"wlk_{secrets.token_urlsafe(32)}"
    key_hash = _hmac_key_hash(raw_key)
    return raw_key, key_hash


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def validate_password(password: str) -> list[str]:
    """Validate password complexity. Returns list of issues (empty = valid).

    S-16: Requires at least 1 uppercase, 1 lowercase, 1 digit, and 12+ chars.
    """
    issues = []
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least 1 uppercase letter")
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least 1 lowercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least 1 digit")
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


def authenticate_user(session: Session, email: str, password: str) -> User | dict | None:
    """Authenticate a user by email and password with lockout protection.

    Returns:
        User: if authentication succeeded and MFA is not enabled.
        dict: if password is correct but MFA is required (``{"mfa_required": True, ...}``).
        None: if authentication failed.
    """
    user = session.query(User).filter(User.email == email, User.is_active == True).first()  # noqa: E712

    if not user:
        # S-13: Dummy verify to prevent timing oracle — use a pre-computed
        # realistic hash so the verify function takes the same time as a real one
        verify_password("dummy-timing-oracle-prevention", _DUMMY_HASH)
        return None

    # Check lockout
    if user.locked_until:
        now = datetime.now(timezone.utc)
        if user.locked_until.tzinfo is None:
            user.locked_until = user.locked_until.replace(tzinfo=timezone.utc)
        if now < user.locked_until:
            log.warning("Login attempt on locked account: %s (locked until %s)", email, user.locked_until)
            return None
        # Lockout expired — reset
        user.failed_login_count = 0
        user.locked_until = None

    if verify_password(password, user.hashed_password):
        # Force re-hash legacy passwords on successful login
        if not user.hashed_password.startswith(("$2b$", "pbkdf2:")):
            log.info("Migrating legacy password hash for user %s", user.email)
            user.hashed_password = hash_password(password)
        # Success — reset failure counter
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)

        # #21: If MFA is enabled, return partial auth — do not complete login
        if user.mfa_enabled:
            log.info("MFA required for user %s — returning partial auth", user.email)
            return {
                "mfa_required": True,
                "user_id": user.id,
                "email": user.email,
            }

        return user

    # Failed — increment counter
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        log.warning(
            "Account locked: %s after %d failed attempts (locked for %d minutes)",
            email, user.failed_login_count, LOCKOUT_MINUTES,
        )
    return None


def authenticate_api_key(session: Session, raw_key: str) -> tuple[User | None, APIKey | None]:
    """Authenticate by API key.

    S-5: Uses HMAC-SHA256 for key hashing. Falls back to plain SHA-256 for
    legacy keys that were hashed before the HMAC migration.
    """
    key_hash = _hmac_key_hash(raw_key)
    # Also compute legacy hash for backward compatibility during migration
    legacy_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    from sqlalchemy import or_
    api_key = session.query(APIKey).filter(
        or_(APIKey.key_hash == key_hash, APIKey.key_hash == legacy_hash),
        APIKey.is_active == True,  # noqa: E712
    ).first()
    if not api_key:
        return None, None
    # S-5: Migrate legacy plain SHA-256 hashes to HMAC on successful auth
    if api_key.key_hash == legacy_hash and api_key.key_hash != key_hash:
        log.info("Migrating API key %s from SHA-256 to HMAC-SHA256", api_key.id[:8])
        api_key.key_hash = key_hash
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


# S-13: Pre-compute a realistic dummy hash at module load for timing oracle prevention.
# This ensures authenticate_user takes the same time whether the user exists or not.
_DUMMY_HASH: str = hash_password("dummy-timing-oracle-prevention")


# ---------------------------------------------------------------------------
# MFA / TOTP (#21)
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Generate a base32-encoded TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a 6-digit TOTP code against a secret. Allow +/-window time steps."""
    key = base64.b32decode(secret)
    for offset in range(-window, window + 1):
        counter = struct.pack(">Q", int(time.time()) // 30 + offset)
        h = hmac.new(key, counter, hashlib.sha1).digest()
        o = h[-1] & 0x0F
        token = str(
            (struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1000000
        ).zfill(6)
        if hmac.compare_digest(token, code):
            return True
    return False


def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """Generate backup codes. Returns (plaintext_codes, hashed_codes)."""
    codes = [secrets.token_hex(4) for _ in range(count)]
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
    return codes, hashed


def enroll_mfa(user_id: str, session: Session) -> dict:
    """Start MFA enrollment -- generate secret and return provisioning URI.

    The caller (API route) is responsible for returning the provisioning URI
    and backup codes to the user. The MFA is not active until ``confirm_mfa``
    is called with a valid TOTP code.
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")
    if user.mfa_enabled:
        raise ValueError("MFA is already enabled for this user")

    totp_secret = generate_totp_secret()
    plaintext_codes, hashed_codes = generate_backup_codes()

    # Store secret and hashed backup codes (MFA not yet active)
    user.mfa_secret = totp_secret
    user.mfa_backup_codes = hashed_codes
    session.flush()

    # otpauth URI for QR code generation (RFC 6238 / Google Authenticator)
    provisioning_uri = (
        f"otpauth://totp/Warlock:{user.email}"
        f"?secret={totp_secret}&issuer=Warlock&digits=6&period=30"
    )

    log.info("MFA enrollment started for user %s", user.email)
    return {
        "provisioning_uri": provisioning_uri,
        "secret": totp_secret,
        "backup_codes": plaintext_codes,
    }


def confirm_mfa(user_id: str, code: str, session: Session) -> bool:
    """Confirm MFA enrollment by verifying the first TOTP code.

    This activates MFA on the account. Must be called after ``enroll_mfa``.
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")
    if not user.mfa_secret:
        raise ValueError("MFA enrollment not started -- call enroll_mfa first")
    if user.mfa_enabled:
        raise ValueError("MFA is already confirmed and active")

    if verify_totp(user.mfa_secret, code):
        user.mfa_enabled = True
        user.mfa_verified_at = datetime.now(timezone.utc)
        session.flush()
        log.info("MFA confirmed and activated for user %s", user.email)
        return True

    log.warning("MFA confirmation failed for user %s -- invalid TOTP code", user.email)
    return False


def verify_mfa_login(user_id: str, code: str, session: Session) -> bool:
    """Verify MFA code during login.

    Called after password authentication returns a partial auth (mfa_required).
    Accepts either a valid TOTP code or a one-time backup code.
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")
    if not user.mfa_enabled or not user.mfa_secret:
        raise ValueError("MFA is not enabled for this user")

    # Try TOTP first
    if verify_totp(user.mfa_secret, code):
        log.info("MFA login verified via TOTP for user %s", user.email)
        return True

    # Try backup code
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if user.mfa_backup_codes and code_hash in user.mfa_backup_codes:
        # Consume the backup code (one-time use)
        remaining = [c for c in user.mfa_backup_codes if c != code_hash]
        user.mfa_backup_codes = remaining
        session.flush()
        log.info(
            "MFA login verified via backup code for user %s (%d codes remaining)",
            user.email, len(remaining),
        )
        return True

    log.warning("MFA login verification failed for user %s", user.email)
    return False
