"""Databricks normalizer — transforms raw Databricks API responses into Findings.

Handles clusters, Unity Catalog, audit logs, and SQL warehouses.
Flags: unencrypted clusters, tables without ACL, terminated clusters with secrets,
admin activity in audit logs.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DatabricksNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "databricks_clusters": "_normalize_clusters",
        "databricks_unity_catalog": "_normalize_unity_catalog",
        "databricks_audit_logs": "_normalize_audit_logs",
        "databricks_sql_warehouses": "_normalize_sql_warehouses",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "databricks" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Databricks findings."""
        return {
            "raw_event_id": raw.id,
            "source": "databricks",
            "source_type": SourceType.DATA_GOVERNANCE,
            "provider": "databricks",
            "observed_at": raw.observed_at,
        }

    # -- Clusters --

    def _normalize_clusters(self, raw: RawEventData) -> list[FindingData]:
        """Inventory clusters; flag unencrypted and terminated clusters with secrets."""
        findings = []
        clusters = raw.raw_data.get("clusters", [])

        for cluster in clusters:
            cluster_id = cluster.get("cluster_id", "")
            cluster_name = cluster.get("cluster_name", "")
            state = cluster.get("state", "")
            creator = cluster.get("creator_user_name", "")
            spark_version = cluster.get("spark_version", "")
            node_type = cluster.get("node_type_id", "")
            num_workers = cluster.get("num_workers", 0)

            # Check encryption
            aws_attrs = cluster.get("aws_attributes", {})
            aws_attrs.get("ebs_volume_type", "") != "" or cluster.get(
                "enable_elastic_disk", False
            )
            has_encryption = bool(
                cluster.get("cluster_log_conf", {}).get("s3", {}).get("kms_key", "")
            )

            # Check for env secrets
            spark_env = cluster.get("spark_env_vars", {})
            has_secrets_in_env = any(
                key.lower().endswith(("_key", "_secret", "_password", "_token"))
                for key in spark_env
            )

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Databricks cluster: {cluster_name} ({state})",
                    detail={
                        "cluster_id": cluster_id,
                        "cluster_name": cluster_name,
                        "state": state,
                        "creator": creator,
                        "spark_version": spark_version,
                        "node_type": node_type,
                        "num_workers": num_workers,
                        "has_encryption": has_encryption,
                    },
                    resource_id=cluster_id,
                    resource_type="databricks_cluster",
                    resource_name=cluster_name,
                    severity="info",
                )
            )

            # Flag unencrypted clusters
            if not has_encryption and state == "RUNNING":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unencrypted cluster: {cluster_name}",
                        detail={
                            "cluster_id": cluster_id,
                            "cluster_name": cluster_name,
                            "state": state,
                            "has_encryption": False,
                            "issue": "Cluster does not have encryption configured for logs — data at rest may be exposed",
                        },
                        resource_id=cluster_id,
                        resource_type="databricks_cluster",
                        resource_name=cluster_name,
                        severity="high",
                    )
                )

            # Flag clusters with secrets in environment variables
            if has_secrets_in_env:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Cluster with secrets in env vars: {cluster_name}",
                        detail={
                            "cluster_id": cluster_id,
                            "cluster_name": cluster_name,
                            "state": state,
                            "secret_env_vars": [
                                k
                                for k in spark_env
                                if k.lower().endswith(("_key", "_secret", "_password", "_token"))
                            ],
                            "issue": "Cluster has secrets stored in plain-text environment variables — use Databricks secrets scope instead",
                        },
                        resource_id=cluster_id,
                        resource_type="databricks_cluster",
                        resource_name=cluster_name,
                        severity="critical",
                    )
                )

        return findings

    # -- Unity Catalog --

    def _normalize_unity_catalog(self, raw: RawEventData) -> list[FindingData]:
        """Inventory catalogs/tables; flag tables without ACL."""
        findings = []
        catalogs = raw.raw_data.get("catalogs", [])
        tables = raw.raw_data.get("tables", [])

        # Inventory catalogs
        for catalog in catalogs:
            catalog_name = catalog.get("name", "")
            owner = catalog.get("owner", "")
            isolation_mode = catalog.get("isolation_mode", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Unity Catalog: {catalog_name}",
                    detail={
                        "catalog_name": catalog_name,
                        "owner": owner,
                        "isolation_mode": isolation_mode,
                    },
                    resource_id=catalog_name,
                    resource_type="databricks_catalog",
                    resource_name=catalog_name,
                    severity="info",
                )
            )

        # Inventory and check tables
        for table in tables:
            table_name = table.get("full_name", table.get("name", ""))
            table_type = table.get("table_type", "")
            owner = table.get("owner", "")
            data_source_format = table.get("data_source_format", "")
            has_row_filter = bool(table.get("row_filter", None))
            has_column_mask = bool(table.get("column_mask", None))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Unity Catalog table: {table_name}",
                    detail={
                        "table_name": table_name,
                        "table_type": table_type,
                        "owner": owner,
                        "data_source_format": data_source_format,
                        "has_row_filter": has_row_filter,
                        "has_column_mask": has_column_mask,
                    },
                    resource_id=table_name,
                    resource_type="databricks_table",
                    resource_name=table_name,
                    severity="info",
                )
            )

            # Flag tables without owner (no ACL)
            if not owner:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Table without owner: {table_name}",
                        detail={
                            "table_name": table_name,
                            "table_type": table_type,
                            "owner": "",
                            "issue": "Table has no owner assigned — access control cannot be properly enforced",
                        },
                        resource_id=table_name,
                        resource_type="databricks_table",
                        resource_name=table_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Audit Logs --

    def _normalize_audit_logs(self, raw: RawEventData) -> list[FindingData]:
        """Flag admin and sensitive activity in audit logs."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        admin_actions = {
            "createCluster", "deleteCluster", "changeClusterAcl",
            "createToken", "revokeToken", "addAdmin", "removeAdmin",
            "changePermissions", "createSecret", "deleteSecret",
        }

        for entry in logs:
            log_id = str(entry.get("id", entry.get("request_id", "")))
            action = entry.get("action_name", entry.get("action", ""))
            user = entry.get("user_name", entry.get("user_identity", {}).get("email", ""))
            timestamp = entry.get("timestamp", entry.get("event_time", ""))
            service = entry.get("service_name", "")
            source_ip = entry.get("source_ip_address", "")

            if action in admin_actions:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Admin activity: {action} by {user}",
                        detail={
                            "log_id": log_id,
                            "action": action,
                            "user": user,
                            "timestamp": timestamp,
                            "service": service,
                            "source_ip": source_ip,
                            "issue": f"Administrative action '{action}' detected — review for unauthorized changes",
                        },
                        resource_id=log_id,
                        resource_type="databricks_audit_log",
                        resource_name=f"{action}:{user}",
                        severity="high",
                    )
                )

        return findings

    # -- SQL Warehouses --

    def _normalize_sql_warehouses(self, raw: RawEventData) -> list[FindingData]:
        """Inventory SQL warehouses."""
        findings = []
        warehouses = raw.raw_data.get("warehouses", [])

        for wh in warehouses:
            wh_id = wh.get("id", "")
            wh_name = wh.get("name", "")
            state = wh.get("state", "")
            cluster_size = wh.get("cluster_size", "")
            num_clusters = wh.get("num_clusters", 0)
            max_num_clusters = wh.get("max_num_clusters", 0)
            auto_stop_mins = wh.get("auto_stop_mins", 0)
            enable_serverless = wh.get("enable_serverless_compute", False)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SQL warehouse: {wh_name} ({state})",
                    detail={
                        "warehouse_id": wh_id,
                        "warehouse_name": wh_name,
                        "state": state,
                        "cluster_size": cluster_size,
                        "num_clusters": num_clusters,
                        "max_num_clusters": max_num_clusters,
                        "auto_stop_mins": auto_stop_mins,
                        "enable_serverless": enable_serverless,
                    },
                    resource_id=wh_id,
                    resource_type="databricks_sql_warehouse",
                    resource_name=wh_name,
                    severity="info",
                )
            )

            # Flag warehouses without auto-stop (cost + security risk)
            if auto_stop_mins == 0 and state == "RUNNING":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"SQL warehouse without auto-stop: {wh_name}",
                        detail={
                            "warehouse_id": wh_id,
                            "warehouse_name": wh_name,
                            "auto_stop_mins": 0,
                            "issue": "SQL warehouse has no auto-stop configured — will run indefinitely, increasing cost and attack surface",
                        },
                        resource_id=wh_id,
                        resource_type="databricks_sql_warehouse",
                        resource_name=wh_name,
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(DatabricksNormalizer())
