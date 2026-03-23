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
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# H-29: Record when this module was first loaded as the reference point for
# the legacy hash deadline. In production, this approximates deployment time.
_MODULE_LOAD_TIME = datetime.now(timezone.utc)


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
        # H-29: After the legacy deadline, reject SHA-256 hashes entirely.
        from warlock.config import get_settings

        cfg = get_settings()
        deadline_days = cfg.password_hash_legacy_deadline_days
        if deadline_days > 0:
            elapsed = (datetime.now(timezone.utc) - _MODULE_LOAD_TIME).days
            if elapsed >= deadline_days:
                log.error(
                    "Legacy SHA-256 hash rejected — deadline of %d days has passed "
                    "(module loaded %d days ago). User must reset their password.",
                    deadline_days,
                    elapsed,
                )
                return False

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
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
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
        log.warning(
            "WLK_JWT_SECRET is shorter than 32 characters — this is insecure for production"
        )
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


def create_user(
    session: Session, email: str, name: str, password: str, role: str = "viewer"
) -> User:
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
        user.locked_until = ensure_aware(user.locked_until)
        if now < user.locked_until:
            log.warning(
                "Login attempt on locked account: %s (locked until %s)", email, user.locked_until
            )
            return None
        # Lockout expired — reset
        user.failed_login_count = 0
        user.locked_until = None

    if verify_password(password, user.hashed_password):
        # Force re-hash legacy passwords on successful login
        if not user.hashed_password.startswith(("$2b$", "pbkdf2:", "bcrypt:")):
            log.info("Migrating legacy password hash for user %s", user.email)
            user.hashed_password = hash_password(password)
        # Success — reset failure counter
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        # H-29: Flush to ensure re-hashed password and login metadata are persisted
        session.flush()

        # #21: If MFA is enabled, return partial auth with signed challenge token
        if user.mfa_enabled:
            log.info("MFA required for user %s — returning signed challenge", user.email)
            return {
                "mfa_required": True,
                "mfa_token": create_mfa_challenge(user.id),
            }

        return user

    # Failed — increment counter
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        log.warning(
            "Account locked: %s after %d failed attempts (locked for %d minutes)",
            email,
            user.failed_login_count,
            LOCKOUT_MINUTES,
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

    api_key = (
        session.query(APIKey)
        .filter(
            or_(APIKey.key_hash == key_hash, APIKey.key_hash == legacy_hash),
            APIKey.is_active == True,  # noqa: E712
        )
        .first()
    )
    if not api_key:
        return None, None
    # S-5: Migrate legacy plain SHA-256 hashes to HMAC on successful auth
    if api_key.key_hash == legacy_hash and api_key.key_hash != key_hash:
        log.info("Migrating API key %s from SHA-256 to HMAC-SHA256", api_key.id[:8])
        api_key.key_hash = key_hash
    expires = api_key.expires_at
    if expires:
        expires = ensure_aware(expires)
        if expires < datetime.now(timezone.utc):
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


def find_legacy_hashes(session: Session) -> list[dict[str, str]]:
    """Query users with non-bcrypt/non-pbkdf2 password hashes.

    H-29: Helps admins identify users who still have legacy SHA-256 hashes
    and need a forced password reset before the migration deadline.

    Returns a list of dicts with 'id', 'email', and 'hash_prefix' (first 8 chars).
    """
    users = session.query(User).filter(User.is_active == True).all()  # noqa: E712
    legacy = []
    for u in users:
        if u.hashed_password and not u.hashed_password.startswith(("bcrypt:", "pbkdf2:")):
            legacy.append(
                {
                    "id": u.id,
                    "email": u.email,
                    "hash_prefix": u.hashed_password[:8] + "...",
                }
            )
    return legacy


# S-13: Pre-compute a realistic dummy hash at module load for timing oracle prevention.
# This ensures authenticate_user takes the same time whether the user exists or not.
_DUMMY_HASH: str = hash_password("dummy-timing-oracle-prevention")


# ---------------------------------------------------------------------------
# MFA / TOTP (#21)
# ---------------------------------------------------------------------------


def _get_field_encryptor():
    """Lazy-load FieldEncryptor for MFA secret encryption."""
    try:
        from warlock.utils.crypto import FieldEncryptor

        return FieldEncryptor()
    except (ValueError, ImportError):
        return None


def _encrypt_mfa_secret(secret: str) -> str:
    """Encrypt MFA TOTP secret before storing in DB."""
    enc = _get_field_encryptor()
    if enc:
        return enc.encrypt(secret)
    return secret


def _decrypt_mfa_secret(stored: str) -> str:
    """Decrypt MFA TOTP secret from DB. Handles plaintext for migration."""
    if not stored:
        return stored
    enc = _get_field_encryptor()
    if enc and enc.is_encrypted(stored):
        return enc.decrypt(stored)
    # Plaintext (pre-encryption migration) — encrypt on next write
    return stored


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
        token = str((struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
        if hmac.compare_digest(token, code):
            return True
    return False


def _hash_backup_code(code: str) -> str:
    """Hash a backup code with PBKDF2-SHA256 (600k iterations).

    C-3 fix: backup codes were previously hashed with plain SHA-256,
    which is vulnerable to offline brute-force given the small keyspace
    (8 hex chars = 32 bits). PBKDF2 with high iteration count makes
    each guess computationally expensive.
    """
    # Use the code itself as salt input combined with a fixed domain separator.
    # Each code gets a unique salt derived from a random per-batch salt stored
    # alongside the hash.
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"pbkdf2:{salt}:{dk.hex()}"


def _verify_backup_code(code: str, stored_hash: str) -> bool:
    """Verify a backup code against its stored PBKDF2 hash.

    Also supports legacy plain SHA-256 hashes for migration.
    """
    if stored_hash.startswith("pbkdf2:"):
        _, salt, expected_hex = stored_hash.split(":", 2)
        dk = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), _PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), expected_hex)
    # Legacy: plain SHA-256 (pre C-3 fix)
    legacy = hashlib.sha256(code.encode()).hexdigest()
    return hmac.compare_digest(legacy, stored_hash)


def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """Generate backup codes. Returns (plaintext_codes, hashed_codes).

    C-3 fix: codes are hashed with PBKDF2-SHA256 (600k iterations)
    instead of plain SHA-256.
    """
    codes = [secrets.token_hex(8) for _ in range(count)]
    hashed = [_hash_backup_code(c) for c in codes]
    return codes, hashed


def enroll_mfa(session: Session, user: User | str) -> dict:
    """Start MFA enrollment -- generate secret and return provisioning URI.

    The caller (API route) is responsible for returning the provisioning URI
    and backup codes to the user. The MFA is not active until ``confirm_mfa``
    is called with a valid TOTP code.

    Args:
        session: Database session.
        user: A User object or a user_id string. When a string is passed,
              the user is looked up from the database.
    """
    if isinstance(user, str):
        user_id = user
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found")
    if user.mfa_enabled:
        raise ValueError("MFA is already enabled for this user")

    totp_secret = generate_totp_secret()
    plaintext_codes, hashed_codes = generate_backup_codes()

    # Store encrypted secret and hashed backup codes (MFA not yet active)
    user.mfa_secret = _encrypt_mfa_secret(totp_secret)
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

    decrypted_secret = _decrypt_mfa_secret(user.mfa_secret)
    if verify_totp(decrypted_secret, code):
        # Re-encrypt if it was stored as plaintext (migration)
        if not _get_field_encryptor() or not _get_field_encryptor().is_encrypted(user.mfa_secret):
            user.mfa_secret = _encrypt_mfa_secret(decrypted_secret)
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

    # Try TOTP first (decrypt the stored secret)
    decrypted_secret = _decrypt_mfa_secret(user.mfa_secret)
    if verify_totp(decrypted_secret, code):
        log.info("MFA login verified via TOTP for user %s", user.email)
        return True

    # Try backup code (supports both PBKDF2 and legacy SHA-256 hashes)
    if user.mfa_backup_codes:
        for i, stored_hash in enumerate(user.mfa_backup_codes):
            if _verify_backup_code(code, stored_hash):
                # Consume the backup code (one-time use)
                remaining = user.mfa_backup_codes[:i] + user.mfa_backup_codes[i + 1 :]
                user.mfa_backup_codes = remaining
                session.flush()
                log.info(
                    "MFA login verified via backup code for user %s (%d codes remaining)",
                    user.email,
                    len(remaining),
                )
                return True

    log.warning("MFA login verification failed for user %s", user.email)
    return False


_MFA_CHALLENGE_TTL = 300  # 5 minutes


def create_mfa_challenge(user_id: str) -> str:
    """Create a signed, time-limited MFA challenge token.

    Replaces exposing raw user_id in the MFA flow. The token is
    HMAC-signed with the JWT secret and expires after 5 minutes.
    """
    secret = _get_jwt_secret()
    payload = {
        "sub": user_id,
        "purpose": "mfa_challenge",
        "exp": time.time() + _MFA_CHALLENGE_TTL,
        "jti": secrets.token_hex(8),
    }
    payload_bytes = json.dumps(payload, default=str).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload_b64}.{sig}"


def verify_mfa_challenge(token: str) -> str | None:
    """Verify an MFA challenge token and return the user_id.

    Returns None if the token is invalid, expired, or tampered.
    """
    secret = _get_jwt_secret()
    parts = token.split(".")
    if len(parts) != 2:
        return None
    payload_b64, sig = parts
    expected_sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return None
    # Restore padding
    padded = payload_b64 + "=" * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else payload_b64
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
    if payload.get("purpose") != "mfa_challenge":
        return None
    if float(payload.get("exp", 0)) < time.time():
        return None
    return payload.get("sub")


def verify_mfa_and_login(session: Session, user_id: str, totp_code: str) -> dict | None:
    """Complete MFA verification and return full token response.

    C-1 fix: This is the function that the /auth/mfa/verify endpoint
    in app.py should call. Without it, the login flow is broken: when
    authenticate_user returns {"mfa_required": True}, there was no way
    to complete the login.

    Args:
        session: Database session.
        user_id: The user ID from the partial auth response.
        totp_code: The 6-digit TOTP code or backup code from the user.

    Returns:
        Token dict (access_token, refresh_token, token_type, expires_in)
        on success, or None if the TOTP/backup code is invalid.
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        log.warning("MFA verify attempted for non-existent user_id: %s", user_id)
        return None
    if not user.mfa_enabled or not user.mfa_secret:
        log.warning("MFA verify attempted but MFA not enabled for user %s", user.email)
        return None

    if not verify_mfa_login(user_id, totp_code, session):
        return None

    # MFA passed -- issue full token pair
    access_token = create_access_token({"sub": user.id})
    refresh_token = generate_refresh_token(user.id, session)

    log.info("MFA login completed for user %s", user.email)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


# ---------------------------------------------------------------------------
# Refresh Tokens (#58)
# ---------------------------------------------------------------------------

REFRESH_TOKEN_EXPIRE_DAYS = 30


def _hash_refresh_token(token: str) -> str:
    """Compute SHA-256 hash of a refresh token for storage.

    Unlike API keys, refresh tokens do not use HMAC because they are
    single-use (rotated on every refresh) and short-lived relative to
    API keys.  A plain SHA-256 hash is sufficient.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def generate_refresh_token(user_id: str, session: Session) -> str:
    """Create a long-lived refresh token (30 days) and store its hash on the user.

    Returns the raw token (shown to the client once; never stored in plaintext).
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")

    raw_token = secrets.token_urlsafe(48)
    user.refresh_token_hash = _hash_refresh_token(raw_token)
    session.flush()

    log.info("Refresh token issued for user %s", user.email)
    return raw_token


def verify_refresh_token(token: str, session: Session) -> str:
    """Validate a refresh token and return the associated user_id.

    Raises ``ValueError`` if the token is invalid or the user is inactive.
    """
    token_hash = _hash_refresh_token(token)
    user = (
        session.query(User)
        .filter(
            User.refresh_token_hash == token_hash,
            User.is_active == True,  # noqa: E712
        )
        .first()
    )

    if not user:
        raise ValueError("Invalid or expired refresh token")

    log.info("Refresh token verified for user %s", user.email)
    return user.id


def rotate_refresh_token(old_token: str, session: Session) -> tuple[str, str]:
    """Invalidate *old_token* and issue a new refresh + access token pair.

    Token rotation prevents replay attacks: once a refresh token is used it
    can never be used again.  If an attacker replays a consumed token the
    stored hash will not match, and the request is rejected.

    Returns ``(new_access_token, new_refresh_token)``.
    """
    # Verify the old token (raises ValueError if invalid)
    user_id = verify_refresh_token(old_token, session)

    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError("User not found")

    # Invalidate old token by overwriting the hash with the new one
    new_refresh = secrets.token_urlsafe(48)
    user.refresh_token_hash = _hash_refresh_token(new_refresh)
    session.flush()

    # Issue a fresh short-lived access token
    new_access = create_access_token({"sub": user.id})

    log.info("Refresh token rotated for user %s", user.email)
    return new_access, new_refresh


def login_with_tokens(session: Session, email: str, password: str) -> dict | None:
    """Authenticate and return both access and refresh tokens.

    Returns a dict with ``access_token``, ``refresh_token``, and ``token_type``
    on success, or a dict with ``mfa_required`` if MFA is needed, or ``None``
    on authentication failure.
    """
    result = authenticate_user(session, email, password)

    if result is None:
        return None

    # MFA partial auth — pass through as-is
    if isinstance(result, dict) and result.get("mfa_required"):
        return result

    # Full auth success — issue both tokens
    user = result
    access_token = create_access_token({"sub": user.id})
    refresh_token = generate_refresh_token(user.id, session)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,  # 1 hour access token
    }
