"""Azure connector — Layer 1 implementation for cloud infrastructure.

Collects from Azure Policy, Defender for Cloud, Entra ID, NSGs,
Key Vault, Storage Accounts, Activity Log, and Azure Monitor.
Each API call becomes a RawEventData with the verbatim response.
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


class AzureConnector(BaseConnector):
    """Collects compliance telemetry from Azure APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401
        except ImportError:
            errors.append("azure-identity not installed. Install with: pip install warlock[azure]")
        if not self.config.settings.get("subscription_id"):
            errors.append("subscription_id is required in connector settings")
        if not self.config.settings.get("tenant_id"):
            errors.append("tenant_id is required in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient

            credential = DefaultAzureCredential()
            client = ResourceManagementClient(credential, self.config.settings["subscription_id"])
            # Simple call to verify credentials
            list(client.resource_groups.list())
            return True
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        from azure.identity import DefaultAzureCredential

        result = ConnectorResult(
            connector_name=self.name,
            source="azure",
            source_type=SourceType.CLOUD,
            provider="azure",
        )

        credential = DefaultAzureCredential()
        subscription_id = self.config.settings["subscription_id"]
        tenant_id = self.config.settings["tenant_id"]

        collectors = [
            ("policy_compliance", self._collect_policy_compliance),
            ("defender_alerts", self._collect_defender_alerts),
            ("entra_sign_ins", self._collect_entra_sign_ins),
            ("network_security_groups", self._collect_nsgs),
            ("key_vault", self._collect_key_vault),
            ("storage_accounts", self._collect_storage_accounts),
            ("activity_log", self._collect_activity_log),
            ("monitor_alerts", self._collect_monitor_alerts),
        ]

        for event_type, collector_fn in collectors:
            try:
                data = collector_fn(credential, subscription_id, tenant_id)
                result.events.append(
                    RawEventData(
                        source="azure",
                        source_type=SourceType.CLOUD,
                        provider="azure",
                        event_type=event_type,
                        raw_data={
                            "subscription_id": subscription_id,
                            "tenant_id": tenant_id,
                            "region": self.config.settings.get("region", ""),
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Azure %s failed: %s", event_type, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Collectors --

    def _collect_policy_compliance(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.policyinsights import PolicyInsightsClient

        client = PolicyInsightsClient(credential, subscription_id)
        states = list(
            client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=subscription_id,
            )
        )
        return {
            "policy_states": [s.as_dict() for s in states],
        }

    def _collect_defender_alerts(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(credential, subscription_id, asc_location="centralus")
        alerts = list(client.alerts.list())
        return {
            "alerts": [a.as_dict() for a in alerts],
        }

    def _collect_entra_sign_ins(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from msgraph.core import GraphClient

        graph_client = GraphClient(credential=credential)
        resp = graph_client.get("/auditLogs/signIns?$top=100")
        return resp.json()

    def _collect_nsgs(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(client.network_security_groups.list_all())
        return {
            "network_security_groups": [nsg.as_dict() for nsg in nsgs],
        }

    def _collect_key_vault(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(client.vaults.list())
        return {
            "vaults": [v.as_dict() for v in vaults],
        }

    def _collect_storage_accounts(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.storage import StorageManagementClient

        client = StorageManagementClient(credential, subscription_id)
        accounts = list(client.storage_accounts.list())
        return {
            "storage_accounts": [a.as_dict() for a in accounts],
        }

    def _collect_activity_log(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.monitor import MonitorManagementClient

        client = MonitorManagementClient(credential, subscription_id)
        # Get last 24h of activity log
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)
        filter_str = (
            f"eventTimestamp ge '{start.isoformat()}' and eventTimestamp le '{now.isoformat()}'"
        )
        logs = list(client.activity_logs.list(filter=filter_str))
        return {
            "activity_logs": [entry.as_dict() for entry in logs],
        }

    def _collect_monitor_alerts(self, credential, subscription_id: str, tenant_id: str) -> dict:
        from azure.mgmt.alertsmanagement import AlertsManagementClient

        client = AlertsManagementClient(credential, subscription_id)
        alerts = list(client.alerts.get_all())
        return {
            "alerts": [a.as_dict() for a in alerts],
        }


# Register
registry.register("azure", AzureConnector)
