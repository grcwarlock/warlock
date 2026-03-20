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
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

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

    Uses Fernet (from the ``cryptography`` package) when available,
    falling back to a stdlib-only XOR+HMAC scheme otherwise.
    """

    def __init__(self, key: str | None = None):
        self.key = key or os.environ.get("WLK_ENCRYPTION_KEY", "")
        if not self.key:
            raise ValueError(
                "Encryption key required. Set WLK_ENCRYPTION_KEY or pass key= argument."
            )
        self._backend: str = "none"
        key_bytes = self.key.encode("utf-8")

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
            self._backend = "fernet"
        else:
            # #15: Refuse to use XOR fallback in production
            wlk_env = os.environ.get("WLK_ENV", "").strip().lower()
            if wlk_env == "production":
                raise RuntimeError(
                    "CRITICAL: The 'cryptography' package is not installed. "
                    "XOR-based encryption is NOT safe for production. "
                    "Install cryptography: pip install cryptography"
                )
            import warnings

            warnings.warn(
                "Using stdlib XOR encryption fallback — NOT safe for production. "
                "Install the 'cryptography' package for Fernet encryption.",
                stacklevel=2,
            )
            self._stdlib = _StdlibEncryptor(key_bytes)
            self._backend = "stdlib"

    @property
    def backend(self) -> str:
        return self._backend

    def encrypt(self, plaintext: str) -> str:
        """Returns ``enc:<base64data>`` string."""
        data = plaintext.encode("utf-8")
        if self._backend == "fernet":
            ct = self._fernet.encrypt(data)
        else:
            ct = self._stdlib.encrypt(data)
        return "enc:" + base64.urlsafe_b64encode(ct).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts ``enc:...`` strings. Returns plaintext."""
        if not self.is_encrypted(ciphertext):
            raise ValueError("Value is not an encrypted field (missing enc: prefix)")
        raw = base64.urlsafe_b64decode(ciphertext[4:])
        if self._backend == "fernet":
            pt = self._fernet.decrypt(raw)
        else:
            pt = self._stdlib.decrypt(raw)
        return pt.decode("utf-8")

    def is_encrypted(self, value: str) -> bool:  # noqa: D401
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
