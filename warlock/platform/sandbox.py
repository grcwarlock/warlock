"""PLT-5: Sandbox / staging environment management.

Creates isolated sandbox environments with their own configuration snapshots.
Sandboxes are logical -- they hold config overrides and metadata rather than
full database copies.  Promotion copies sandbox config into the production
config registry.
"""

from __future__ import annotations

import logging
import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from warlock.config import get_settings

log = logging.getLogger(__name__)

_SANDBOX_STATUSES = frozenset({"active", "promoted", "destroyed"})


class SandboxManager:
    """Lifecycle management for sandbox/staging environments."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # sandbox_id -> sandbox metadata
        self._sandboxes: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_sandbox(
        self,
        name: str,
        source_env: str = "production",
        *,
        config_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new sandbox environment.

        Parameters
        ----------
        name:
            Human-readable name for the sandbox.
        source_env:
            The source environment to snapshot config from.  Defaults to
            ``"production"`` which reads from the current ``get_settings()``.
        config_overrides:
            Optional dict of settings to override in the sandbox.

        Returns the sandbox record.

        Raises ``ValueError`` if a sandbox with the same name already exists.
        """
        with self._lock:
            for sb in self._sandboxes.values():
                if sb["name"] == name and sb["status"] == "active":
                    raise ValueError(f"Active sandbox with name '{name}' already exists")

            sandbox_id = str(uuid4())
            now = datetime.now(timezone.utc).isoformat()

            # Snapshot the current settings as the base config.
            base_config = self._snapshot_settings()
            if config_overrides:
                base_config.update(config_overrides)

            sandbox: dict[str, Any] = {
                "sandbox_id": sandbox_id,
                "name": name,
                "source_env": source_env,
                "status": "active",
                "config": base_config,
                "created_at": now,
                "promoted_at": None,
                "destroyed_at": None,
            }
            self._sandboxes[sandbox_id] = sandbox
            log.info("Created sandbox %s (%s) from %s", sandbox_id, name, source_env)
            return self._safe_copy(sandbox)

    def destroy_sandbox(self, sandbox_id: str) -> dict[str, Any]:
        """Destroy (soft-delete) a sandbox.

        Raises ``KeyError`` if not found.
        Raises ``ValueError`` if already destroyed.
        """
        sandbox = self._get_sandbox(sandbox_id)
        if sandbox["status"] == "destroyed":
            raise ValueError(f"Sandbox {sandbox_id} is already destroyed")
        with self._lock:
            sandbox["status"] = "destroyed"
            sandbox["destroyed_at"] = datetime.now(timezone.utc).isoformat()
        log.info("Destroyed sandbox %s", sandbox_id)
        return self._safe_copy(sandbox)

    def list_sandboxes(self, *, include_destroyed: bool = False) -> list[dict[str, Any]]:
        """Return all sandboxes.

        By default only active and promoted sandboxes are returned.
        """
        with self._lock:
            sandboxes = list(self._sandboxes.values())
        if not include_destroyed:
            sandboxes = [s for s in sandboxes if s["status"] != "destroyed"]
        return [self._safe_copy(s) for s in sandboxes]

    def promote_to_production(self, sandbox_id: str) -> dict[str, Any]:
        """Promote a sandbox's configuration for production use.

        This marks the sandbox as promoted and returns the config diff that
        should be applied.  Actual application of config to the running system
        is the caller's responsibility (e.g. updating environment variables or
        a config store).

        Raises ``KeyError`` if not found.
        Raises ``ValueError`` if sandbox is not active.
        """
        sandbox = self._get_sandbox(sandbox_id)
        if sandbox["status"] != "active":
            raise ValueError(
                f"Only active sandboxes can be promoted; current status is '{sandbox['status']}'"
            )

        production_config = self._snapshot_settings()
        sandbox_config = sandbox["config"]

        # Compute the diff: keys that differ between sandbox and current production.
        diff: dict[str, dict[str, Any]] = {}
        all_keys = set(production_config) | set(sandbox_config)
        for key in sorted(all_keys):
            prod_val = production_config.get(key)
            sb_val = sandbox_config.get(key)
            if prod_val != sb_val:
                diff[key] = {"production": prod_val, "sandbox": sb_val}

        with self._lock:
            sandbox["status"] = "promoted"
            sandbox["promoted_at"] = datetime.now(timezone.utc).isoformat()

        log.info("Promoted sandbox %s with %d config changes", sandbox_id, len(diff))
        return {
            "sandbox_id": sandbox_id,
            "name": sandbox["name"],
            "status": "promoted",
            "config_diff": diff,
            "promoted_at": sandbox["promoted_at"],
        }

    def get_sandbox(self, sandbox_id: str) -> dict[str, Any]:
        """Return a single sandbox record."""
        return self._safe_copy(self._get_sandbox(sandbox_id))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sandbox(self, sandbox_id: str) -> dict[str, Any]:
        with self._lock:
            try:
                return self._sandboxes[sandbox_id]
            except KeyError:
                raise KeyError(f"Sandbox '{sandbox_id}' not found") from None

    @staticmethod
    def _snapshot_settings() -> dict[str, Any]:
        """Snapshot safe (non-secret) settings as a dict."""
        settings = get_settings()
        # Only snapshot non-secret fields.
        safe_keys = [
            "database_url",
            "pipeline_batch_size",
            "pipeline_timeout_seconds",
            "aws_enabled",
            "azure_enabled",
            "gcp_enabled",
        ]
        result: dict[str, Any] = {}
        for key in safe_keys:
            val = getattr(settings, key, None)
            if val is not None:
                # Convert non-serializable types to string.
                if isinstance(val, (list, dict, str, int, float, bool)):
                    result[key] = val
                else:
                    result[key] = str(val)
        return result

    @staticmethod
    def _safe_copy(sandbox: dict[str, Any]) -> dict[str, Any]:
        return deepcopy(sandbox)
