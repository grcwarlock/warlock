"""PLT-1: Multi-tenancy foundation.

Provides tenant isolation via a lightweight in-memory registry with optional
JSON persistence.  Tenant context is expressed as SQLAlchemy query filters so
that all database access is automatically scoped.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Query

log = logging.getLogger(__name__)

_DEFAULT_TENANT_DIR = os.environ.get("WLK_TENANT_DIR", "")


class TenantManager:
    """Manages tenant lifecycle and query isolation."""

    def __init__(self, *, persist_dir: str | None = None) -> None:
        self._lock = threading.Lock()
        # tenant_id -> tenant metadata dict
        self._tenants: dict[str, dict[str, Any]] = {}
        self._persist_dir: Path | None = None

        directory = persist_dir or _DEFAULT_TENANT_DIR
        if directory:
            self._persist_dir = Path(directory)
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            self._load_persisted()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_tenant(
        self,
        name: str,
        config_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new tenant with optional config overrides.

        Returns the full tenant record including the generated ``tenant_id``.

        Raises ``ValueError`` if a tenant with the same name already exists.
        """
        with self._lock:
            for t in self._tenants.values():
                if t["name"] == name:
                    raise ValueError(f"Tenant with name '{name}' already exists")

            tenant_id = str(uuid4())
            now = datetime.now(timezone.utc).isoformat()
            tenant: dict[str, Any] = {
                "tenant_id": tenant_id,
                "name": name,
                "config_overrides": config_overrides or {},
                "created_at": now,
                "is_active": True,
            }
            self._tenants[tenant_id] = tenant
            self._persist(tenant_id)
            log.info("Created tenant %s (%s)", tenant_id, name)
            return dict(tenant)

    def get_tenant_context(self, tenant_id: str) -> dict[str, Any]:
        """Return scoping filters for DB queries bound to *tenant_id*.

        The returned dict contains:
        - ``tenant_id``: the tenant identifier to filter on
        - ``filter_column``: the recommended column name for scoping
        - ``config_overrides``: tenant-specific config values

        Raises ``KeyError`` if the tenant does not exist.
        """
        tenant = self._get_tenant(tenant_id)
        return {
            "tenant_id": tenant_id,
            "filter_column": "account_id",
            "config_overrides": dict(tenant.get("config_overrides", {})),
            "is_active": tenant["is_active"],
        }

    def list_tenants(self, *, include_inactive: bool = False) -> list[dict[str, Any]]:
        """Return all registered tenants.

        By default only active tenants are returned.  Pass
        ``include_inactive=True`` to include deactivated tenants.
        """
        with self._lock:
            tenants = list(self._tenants.values())
        if not include_inactive:
            tenants = [t for t in tenants if t.get("is_active", True)]
        return [dict(t) for t in tenants]

    def deactivate_tenant(self, tenant_id: str) -> None:
        """Soft-delete a tenant by marking it inactive."""
        tenant = self._get_tenant(tenant_id)
        with self._lock:
            tenant["is_active"] = False
            self._persist(tenant_id)
        log.info("Deactivated tenant %s", tenant_id)

    def isolate_query(self, query: Query, tenant_id: str, *, column: str = "account_id") -> Query:
        """Add a tenant isolation filter to a SQLAlchemy query.

        Parameters
        ----------
        query:
            An existing SQLAlchemy ORM query.
        tenant_id:
            The tenant whose data should be visible.
        column:
            The model attribute name used for tenant scoping.  Defaults to
            ``account_id`` which exists on :class:`Finding`.

        Returns the query with an additional ``.filter()`` clause.  If the
        query's primary entity does not have *column*, the query is returned
        unmodified with a warning logged.
        """
        self._get_tenant(tenant_id)  # validate tenant exists
        entity = _get_query_entity(query)
        if entity is None:
            log.warning("Cannot isolate query: no primary entity found")
            return query
        col = getattr(entity, column, None)
        if col is None:
            log.warning(
                "Entity %s has no column '%s'; skipping tenant filter",
                entity.__name__,
                column,
            )
            return query
        return query.filter(col == tenant_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_tenant(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            try:
                return self._tenants[tenant_id]
            except KeyError:
                raise KeyError(f"Tenant '{tenant_id}' not found") from None

    def _persist(self, tenant_id: str) -> None:
        if self._persist_dir is None:
            return
        path = self._persist_dir / f"{tenant_id}.json"
        try:
            path.write_text(json.dumps(self._tenants[tenant_id], indent=2))
        except OSError:
            log.exception("Failed to persist tenant %s", tenant_id)

    def _load_persisted(self) -> None:
        if self._persist_dir is None:
            return
        for path in self._persist_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                tid = data.get("tenant_id")
                if tid:
                    self._tenants[tid] = data
            except (json.JSONDecodeError, OSError):
                log.exception("Failed to load tenant file %s", path)


def _get_query_entity(query: Query) -> type | None:
    """Extract the primary mapped class from a SQLAlchemy Query."""
    try:
        return query.column_descriptions[0]["entity"]
    except (IndexError, KeyError, AttributeError):
        return None
