"""Databricks connector — Layer 1 implementation for data governance.

Collects clusters (encryption, ACL), Unity Catalog (tables, access controls),
audit logs, and SQL warehouses via the Databricks REST API 2.0
with Bearer token auth.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class DatabricksConnector(BaseConnector):
    """Collects compliance telemetry from Databricks REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[databricks]")
        if not self.get_secret("WLK_DATABRICKS_HOST"):
            errors.append("WLK_DATABRICKS_HOST not set")
        if not self.get_secret("WLK_DATABRICKS_TOKEN"):
            errors.append("WLK_DATABRICKS_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            host = self.get_secret("WLK_DATABRICKS_HOST").rstrip("/")
            resp = client.get(f"https://{host}/api/2.0/clusters/list")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="databricks",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="databricks",
        )

        host = self.get_secret("WLK_DATABRICKS_HOST").rstrip("/")
        base_url = f"https://{host}/api/2.0"

        self._collect_clusters(base_url, result)
        self._collect_unity_catalog(base_url, result)
        self._collect_audit_logs(base_url, result)
        self._collect_sql_warehouses(base_url, result)

        result.complete()
        return result

    # -- Client --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_DATABRICKS_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="databricks",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="databricks",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_clusters(self, base_url: str, result: ConnectorResult) -> None:
        """Collect Databricks clusters with encryption and ACL info."""
        try:
            client = self._client()
            resp = client.get(f"{base_url}/clusters/list")
            resp.raise_for_status()
            clusters = resp.json().get("clusters", [])
            result.events.append(self._raw_event("databricks_clusters", {"clusters": clusters}))
        except Exception as e:
            log.debug("Databricks clusters collection failed: %s", e)
            result.errors.append(f"databricks_clusters: {e}")

    def _collect_unity_catalog(self, base_url: str, result: ConnectorResult) -> None:
        """Collect Unity Catalog tables and access controls."""
        try:
            client = self._client()
            # List catalogs
            resp = client.get(f"{base_url}/unity-catalog/catalogs")
            resp.raise_for_status()
            catalogs = resp.json().get("catalogs", [])

            tables = []
            for catalog in catalogs:
                catalog_name = catalog.get("name", "")
                # List schemas in each catalog
                try:
                    schema_resp = client.get(
                        f"{base_url}/unity-catalog/schemas",
                        params={"catalog_name": catalog_name},
                    )
                    schema_resp.raise_for_status()
                    schemas = schema_resp.json().get("schemas", [])
                    for schema in schemas:
                        schema_name = schema.get("name", "")
                        try:
                            table_resp = client.get(
                                f"{base_url}/unity-catalog/tables",
                                params={
                                    "catalog_name": catalog_name,
                                    "schema_name": schema_name,
                                },
                            )
                            table_resp.raise_for_status()
                            tables.extend(table_resp.json().get("tables", []))
                        except Exception:
                            pass
                except Exception:
                    pass

            result.events.append(
                self._raw_event(
                    "databricks_unity_catalog",
                    {"catalogs": catalogs, "tables": tables},
                )
            )
        except Exception as e:
            log.debug("Databricks Unity Catalog collection failed: %s", e)
            result.errors.append(f"databricks_unity_catalog: {e}")

    def _collect_audit_logs(self, base_url: str, result: ConnectorResult) -> None:
        """Collect Databricks audit logs."""
        try:
            client = self._client()
            resp = client.get(
                f"{base_url}/audit-logs",
                params={"limit": "500"},
            )
            resp.raise_for_status()
            logs = resp.json().get("events", resp.json().get("logs", []))
            result.events.append(self._raw_event("databricks_audit_logs", {"logs": logs}))
        except Exception as e:
            log.debug("Databricks audit logs collection failed: %s", e)
            result.errors.append(f"databricks_audit_logs: {e}")

    def _collect_sql_warehouses(self, base_url: str, result: ConnectorResult) -> None:
        """Collect SQL warehouses."""
        try:
            client = self._client()
            resp = client.get(f"{base_url}/sql/warehouses")
            resp.raise_for_status()
            warehouses = resp.json().get("warehouses", [])
            result.events.append(
                self._raw_event("databricks_sql_warehouses", {"warehouses": warehouses})
            )
        except Exception as e:
            log.debug("Databricks SQL warehouses collection failed: %s", e)
            result.errors.append(f"databricks_sql_warehouses: {e}")


# Register
registry.register("databricks", DatabricksConnector)
