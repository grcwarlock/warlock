"""GCP connector — Layer 1 implementation for cloud infrastructure.

Collects from Security Command Center, IAM, Compute firewall rules,
Cloud Storage, Cloud Audit Logs, and GKE clusters.
Each API call becomes a RawEventData with the verbatim response.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)


class GCPConnector(BaseConnector):
    """Collects compliance telemetry from GCP APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            from google.auth import default as google_auth_default  # noqa: F401
        except ImportError:
            errors.append(
                "google-auth not installed. Install with: pip install warlock[gcp]"
            )
        if not self.config.settings.get("project_id"):
            errors.append("project_id is required in connector settings")
        if not self.config.settings.get("organization_id"):
            errors.append("organization_id is required in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient()
            project_id = self.config.settings["project_id"]
            client.get_project(name=f"projects/{project_id}")
            return True
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gcp",
            source_type=SourceType.CLOUD,
            provider="gcp",
        )

        project_id = self.config.settings["project_id"]
        organization_id = self.config.settings["organization_id"]

        collectors = [
            ("scc_findings", self._collect_scc_findings),
            ("iam_policies", self._collect_iam_policies),
            ("compute_firewall_rules", self._collect_firewall_rules),
            ("storage_buckets", self._collect_storage_buckets),
            ("audit_logs", self._collect_audit_logs),
            ("gke_clusters", self._collect_gke_clusters),
        ]

        for event_type, collector_fn in collectors:
            try:
                data = collector_fn(project_id, organization_id)
                result.events.append(RawEventData(
                    source="gcp",
                    source_type=SourceType.CLOUD,
                    provider="gcp",
                    event_type=event_type,
                    raw_data={
                        "project_id": project_id,
                        "organization_id": organization_id,
                        "response": data,
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("GCP %s failed: %s", event_type, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Collectors --

    def _collect_scc_findings(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import securitycenter_v1

        client = securitycenter_v1.SecurityCenterClient()
        parent = f"organizations/{organization_id}/sources/-"
        findings = list(client.list_findings(request={"parent": parent}))
        return {
            "findings": [
                type(f.finding).to_dict(f.finding) for f in findings
            ],
        }

    def _collect_iam_policies(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import resourcemanager_v3

        client = resourcemanager_v3.ProjectsClient()
        policy = client.get_iam_policy(
            request={"resource": f"projects/{project_id}"}
        )
        bindings = []
        for binding in policy.bindings:
            bindings.append({
                "role": binding.role,
                "members": list(binding.members),
            })
        return {
            "bindings": bindings,
        }

    def _collect_firewall_rules(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import compute_v1

        client = compute_v1.FirewallsClient()
        firewalls = list(client.list(project=project_id))
        return {
            "firewall_rules": [
                type(fw).to_dict(fw) for fw in firewalls
            ],
        }

    def _collect_storage_buckets(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import storage

        client = storage.Client(project=project_id)
        buckets = list(client.list_buckets())
        return {
            "buckets": [
                {
                    "name": b.name,
                    "location": b.location,
                    "storage_class": b.storage_class,
                    "versioning_enabled": b.versioning_enabled,
                    "iam_configuration": {
                        "uniform_bucket_level_access_enabled": (
                            b.iam_configuration.get(
                                "uniformBucketLevelAccess", {}
                            ).get("enabled", False)
                            if isinstance(b.iam_configuration, dict)
                            else False
                        ),
                    },
                    "labels": dict(b.labels) if b.labels else {},
                }
                for b in buckets
            ],
        }

    def _collect_audit_logs(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import logging as cloud_logging

        client = cloud_logging.Client(project=project_id)
        # Get last 24h of admin activity audit logs
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)
        filter_str = (
            f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
            f'AND timestamp>="{start.isoformat()}" '
            f'AND timestamp<="{now.isoformat()}"'
        )
        entries = list(client.list_entries(filter_=filter_str, max_results=500))
        return {
            "log_entries": [
                {
                    "log_name": e.log_name,
                    "severity": e.severity,
                    "timestamp": str(e.timestamp),
                    "payload": e.payload if isinstance(e.payload, dict) else str(e.payload),
                    "resource": {
                        "type": e.resource.type,
                        "labels": dict(e.resource.labels),
                    },
                }
                for e in entries
            ],
        }

    def _collect_gke_clusters(
        self, project_id: str, organization_id: str
    ) -> dict:
        from google.cloud import container_v1

        client = container_v1.ClusterManagerClient()
        parent = f"projects/{project_id}/locations/-"
        response = client.list_clusters(parent=parent)
        return {
            "clusters": [
                type(c).to_dict(c) for c in response.clusters
            ] if response.clusters else [],
        }


# Register
registry.register("gcp", GCPConnector)
