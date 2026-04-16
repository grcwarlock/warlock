"""Field-level encryption and sensitive data masking."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False

# ---------------------------------------------------------------------------
# Default sensitive field patterns
# ---------------------------------------------------------------------------

_DEFAULT_SENSITIVE_NAMES = {
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "api_key",
    "apikey",
    "api_secret",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "auth_token",
    "bearer",
    "ssn",
    "social_security",
}

_SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),  # JWT
    re.compile(r"^(sk|pk|rk)[-_][A-Za-z0-9]{20,}$"),  # Stripe-style API keys
    re.compile(r"^AKIA[0-9A-Z]{16}$"),  # AWS access key IDs
    re.compile(r"^ghp_[A-Za-z0-9]{36}$"),  # GitHub PATs
    re.compile(r"^xox[bpas]-[A-Za-z0-9-]+$"),  # Slack tokens
    re.compile(r"^[0-9a-f]{40}$"),  # 40-char hex (potential secrets)
]


# ---------------------------------------------------------------------------
# Fallback AES-like encryption using stdlib only
# ---------------------------------------------------------------------------


class _StdlibEncryptor:
    """Simple XOR-based encryption with HMAC for integrity.

    NOT cryptographically strong -- this is the fallback when the
    `cryptography` package is not installed. Use Fernet for production.
    """

    def __init__(self, key_bytes: bytes):
        self._key = hashlib.sha256(key_bytes).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        stream = self._keystream(nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(self._key, nonce + ct, hashlib.sha256).digest()[:16]
        return nonce + tag + ct

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 32:
            raise ValueError("Ciphertext too short")
        nonce = data[:16]
        tag = data[16:32]
        ct = data[32:]
        expected_tag = hmac.new(self._key, nonce + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Integrity check failed -- ciphertext may be tampered")
        stream = self._keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream))

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        blocks = (length // 32) + 1
        stream = b""
        for i in range(blocks):
            stream += hashlib.sha256(self._key + nonce + i.to_bytes(4, "big")).digest()
        return stream[:length]


# ---------------------------------------------------------------------------
# FieldEncryptor
# ---------------------------------------------------------------------------


class FieldEncryptor:
    """Encrypt/decrypt individual field values at rest.

    N32: supports two backends:
    - ``fernet``  — AES-128-CBC + HMAC-SHA256 (legacy default, kept so
                    existing ciphertext remains decryptable forever).
    - ``aes-gcm-256`` — AES-256-GCM (modern AEAD; use for new deployments).

    The ciphertext format embeds a version tag so backends can coexist:
    - ``enc:<b64>``    — legacy Fernet (backwards compatible)
    - ``enc:v2:<b64>`` — AES-256-GCM nonce(12) || tag(16) || ct

    Selection is via ``WLK_ENCRYPTION_BACKEND`` (``fernet`` or ``aes-gcm-256``;
    default ``fernet``). Decryption auto-detects the version tag.
    """

    def __init__(self, key: str | None = None):
        self.key = key or os.environ.get("WLK_ENCRYPTION_KEY", "")
        if not self.key:
            raise ValueError(
                "Encryption key required. Set WLK_ENCRYPTION_KEY or pass key= argument."
            )
        self._backend: str = "none"
        key_bytes = self.key.encode("utf-8")
        chosen = os.environ.get("WLK_ENCRYPTION_BACKEND", "fernet").strip().lower()

        if _HAS_FERNET:
            # #16: Use a per-deployment salt derived from the encryption key
            # instead of a static salt. The salt is deterministic per-key so
            # existing ciphertext remains decryptable with the same key.
            salt = hashlib.sha256(key_bytes + b"warlock-grc-field-enc-v1").digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480_000,
            )
            derived = base64.urlsafe_b64encode(kdf.derive(key_bytes))
            self._fernet = Fernet(derived)

            # N32: also derive a 32-byte AES-256-GCM key for the modern backend.
            gcm_salt = hashlib.sha256(key_bytes + b"warlock-grc-field-enc-aesgcm-v2").digest()[:16]
            gcm_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=gcm_salt,
                iterations=480_000,
            )
            self._aesgcm_key = gcm_kdf.derive(key_bytes)
            self._backend = "aes-gcm-256" if chosen == "aes-gcm-256" else "fernet"
        else:
            # N31 fix: Refuse to use XOR fallback in ANY non-development env.
            # The XOR stream cipher is not authenticated against modern attacks
            # and even in test/staging produces fixtures that may end up in
            # repos. Only `development` allows the fallback.
            wlk_env = os.environ.get("WLK_ENV", "").strip().lower()
            if wlk_env and wlk_env != "development":
                raise RuntimeError(
                    "CRITICAL: The 'cryptography' package is not installed. "
                    f"XOR-based encryption is NOT safe in env={wlk_env}. "
                    "Install cryptography: pip install cryptography"
                )
            import warnings

            warnings.warn(
                "Using stdlib XOR encryption fallback — NOT safe outside dev. "
                "Install the 'cryptography' package for Fernet encryption.",
                stacklevel=2,
            )
            self._stdlib = _StdlibEncryptor(key_bytes)
            self._backend = "stdlib"

    @property
    def backend(self) -> str:
        return self._backend

    def encrypt(self, plaintext: str) -> str:
        """Returns ``enc:<base64data>`` (Fernet) or ``enc:v2:<b64>`` (AES-GCM)."""
        data = plaintext.encode("utf-8")
        if self._backend == "aes-gcm-256":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            aes = AESGCM(self._aesgcm_key)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, data, None)  # ct includes 16-byte tag
            return "enc:v2:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")
        if self._backend == "fernet":
            ct = self._fernet.encrypt(data)
            return "enc:" + base64.urlsafe_b64encode(ct).decode("ascii")
        ct = self._stdlib.encrypt(data)
        return "enc:" + base64.urlsafe_b64encode(ct).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts ``enc:...`` strings. Auto-detects backend by version tag."""
        if not self.is_encrypted(ciphertext):
            raise ValueError("Value is not an encrypted field (missing enc: prefix)")
        # N32: detect AES-GCM v2 ciphertext
        if ciphertext.startswith("enc:v2:"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            blob = base64.urlsafe_b64decode(ciphertext[7:])
            if len(blob) < 28:  # 12 nonce + 16 tag minimum
                raise ValueError("AES-GCM ciphertext too short")
            nonce, ct = blob[:12], blob[12:]
            aes = AESGCM(self._aesgcm_key)
            pt = aes.decrypt(nonce, ct, None)
            return pt.decode("utf-8")
        raw = base64.urlsafe_b64decode(ciphertext[4:])
        if self._backend in ("fernet", "aes-gcm-256") and hasattr(self, "_fernet"):
            # Try Fernet — handles legacy ciphertext even when default is GCM
            pt = self._fernet.decrypt(raw)
        else:
            pt = self._stdlib.decrypt(raw)
        return pt.decode("utf-8")

    def is_encrypted(self, value: str) -> bool:
        return isinstance(value, str) and value.startswith("enc:")


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------


def mask_sensitive(
    data: dict,
    fields: list[str] | None = None,
) -> dict:
    """Mask sensitive fields in a dict for API responses.

    Default fields: password, secret, token, key, credential, api_key.
    Replaces value with ``***MASKED***`` or shows last 4 chars for key-like values.
    """
    sensitive = set(fields) if fields else _DEFAULT_SENSITIVE_NAMES
    result = {}
    for k, v in data.items():
        k_lower = k.lower()
        if any(s in k_lower for s in sensitive):
            if isinstance(v, str) and len(v) > 8:
                result[k] = "***" + v[-4:]
            else:
                result[k] = "***MASKED***"
        elif isinstance(v, dict):
            result[k] = mask_sensitive(v, fields)
        elif isinstance(v, list):
            result[k] = [
                mask_sensitive(item, fields) if isinstance(item, dict) else item for item in v
            ]
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# GAP-079: Standalone encrypt/decrypt convenience functions
# ---------------------------------------------------------------------------
#
# Fields that SHOULD be encrypted at rest when stored in the database:
#   - jwt_secret (Settings / env)
#   - api key raw values (never stored, but if cached)
#   - user.mfa_secret (TOTP shared secret)
#   - PII fields subject to GDPR (email, name when flagged)
#   - Any connector credential (client_secret, api_token)
#
# Usage:
#   from warlock.utils.crypto import encrypt_field, decrypt_field
#   encrypted = encrypt_field("sensitive-value")
#   plaintext = decrypt_field(encrypted)


def encrypt_field(value: str, key: str | None = None) -> str:
    """Encrypt a field value for storage at rest.

    Uses FieldEncryptor (Fernet when available, stdlib fallback in dev).
    Returns an ``enc:...`` prefixed string.

    Args:
        value: Plaintext string to encrypt.
        key: Encryption key. Defaults to WLK_ENCRYPTION_KEY from settings.
    """
    enc = FieldEncryptor(key=key)
    return enc.encrypt(value)


def decrypt_field(encrypted: str, key: str | None = None) -> str:
    """Decrypt a field value previously encrypted with ``encrypt_field``.

    Args:
        encrypted: The ``enc:...`` prefixed ciphertext.
        key: Encryption key. Defaults to WLK_ENCRYPTION_KEY from settings.
    """
    enc = FieldEncryptor(key=key)
    return enc.decrypt(encrypted)


def is_encrypted(value: str) -> bool:
    """Return True if the value has the ``enc:`` prefix indicating encryption."""
    return isinstance(value, str) and value.startswith("enc:")


def detect_sensitive_fields(data: dict) -> list[str]:
    """Heuristic detection of fields containing sensitive data.

    Checks field names and value patterns (JWT tokens, API keys, etc.).
    Returns a list of field paths that look sensitive.
    """
    found: list[str] = []

    for key, value in data.items():
        k_lower = key.lower()

        # Check field name
        if any(s in k_lower for s in _DEFAULT_SENSITIVE_NAMES):
            found.append(key)
            continue

        # Check value patterns
        if isinstance(value, str) and value:
            for pattern in _SENSITIVE_VALUE_PATTERNS:
                if pattern.match(value):
                    found.append(key)
                    break

        # Recurse into nested dicts
        if isinstance(value, dict):
            nested = detect_sensitive_fields(value)
            found.extend(f"{key}.{n}" for n in nested)
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, dict):
                    nested = detect_sensitive_fields(item)
                    found.extend(f"{key}[{idx}].{n}" for n in nested)

    return found
