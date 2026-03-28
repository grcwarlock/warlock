"""Secrets backend abstraction with rotation support (GAP-076).

Provides a pluggable backend for connector credential management.
The default ``EnvSecretsBackend`` reads from environment variables;
``VaultSecretsBackend`` optionally integrates with HashiCorp Vault.

Usage:
    from warlock.connectors.secrets_backend import get_secrets_backend
    backend = get_secrets_backend()
    api_key = backend.get_secret("WLK_MY_API_KEY")
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod

log = logging.getLogger(__name__)

try:
    import hvac

    _HAS_HVAC = True
except ImportError:
    hvac = None  # type: ignore[assignment]
    _HAS_HVAC = False


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class SecretsBackend(ABC):
    """Abstraction for secret storage with rotation support."""

    @abstractmethod
    def get_secret(self, name: str) -> str:
        """Retrieve a secret by name. Returns empty string if not found."""
        ...

    @abstractmethod
    def rotate_secret(self, name: str, new_value: str) -> None:
        """Replace the value of an existing secret."""
        ...


# ---------------------------------------------------------------------------
# Environment variable backend (default)
# ---------------------------------------------------------------------------


class EnvSecretsBackend(SecretsBackend):
    """Default backend: reads from and writes to environment variables."""

    def get_secret(self, name: str) -> str:
        return os.environ.get(name, "")

    def rotate_secret(self, name: str, new_value: str) -> None:
        os.environ[name] = new_value
        log.info("Secret %s rotated (env backend)", name)


# ---------------------------------------------------------------------------
# HashiCorp Vault backend (optional)
# ---------------------------------------------------------------------------


class VaultSecretsBackend(SecretsBackend):
    """Optional backend: reads from and writes to HashiCorp Vault.

    Requires the ``hvac`` package: ``pip install hvac``.
    """

    def __init__(
        self,
        vault_url: str | None = None,
        vault_token: str | None = None,
        mount_point: str = "secret",
        path_prefix: str = "warlock",
    ) -> None:
        if not _HAS_HVAC:
            raise RuntimeError(
                "hvac package is required for VaultSecretsBackend. Install with: pip install hvac"
            )
        self._url = vault_url or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self._token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self._mount = mount_point
        self._prefix = path_prefix
        self._client: hvac.Client = hvac.Client(url=self._url, token=self._token)

    def _path(self, name: str) -> str:
        return f"{self._prefix}/{name}"

    def get_secret(self, name: str) -> str:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=self._path(name),
                mount_point=self._mount,
            )
            return resp["data"]["data"].get("value", "")
        except Exception:
            log.debug("Vault read failed for %s, falling back to env", name)
            return os.environ.get(name, "")

    def rotate_secret(self, name: str, new_value: str) -> None:
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=self._path(name),
                secret={"value": new_value},
                mount_point=self._mount,
            )
            log.info("Secret %s rotated in Vault", name)
        except Exception:
            log.exception("Vault write failed for %s", name)
            raise


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_backend: SecretsBackend | None = None


def get_secrets_backend() -> SecretsBackend:
    """Return the configured secrets backend (singleton).

    Reads ``WLK_SECRETS_BACKEND`` env var:
      - ``"vault"`` -> VaultSecretsBackend
      - anything else -> EnvSecretsBackend (default)
    """
    global _backend  # noqa: PLW0603
    if _backend is not None:
        return _backend

    backend_type = os.environ.get("WLK_SECRETS_BACKEND", "env").lower()
    if backend_type == "vault":
        _backend = VaultSecretsBackend()
    else:
        _backend = EnvSecretsBackend()

    log.info("Secrets backend initialized: %s", type(_backend).__name__)
    return _backend


def set_secrets_backend(backend: SecretsBackend) -> None:
    """Override the global secrets backend (useful for testing)."""
    global _backend  # noqa: PLW0603
    _backend = backend
