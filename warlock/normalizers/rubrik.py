"""Rubrik normalizer — transforms raw Rubrik backup API responses into Findings.

Normalizes cluster info and VMs as inventory, SLA domains as inventory.
VMs not protected by an SLA are flagged as high-severity misconfiguration.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RubrikNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Rubrik backup findings."""

    HANDLERS: dict[str, str] = {
        "rubrik_cluster": "_normalize_cluster",
        "rubrik_vms": "_normalize_vms",
        "rubrik_sla_domains": "_normalize_sla_domains",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "rubrik" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "rubrik",
            "source_type": SourceType.BACKUP,
            "provider": "rubrik",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_cluster(self, raw: RawEventData) -> list[FindingData]:
        response = raw.raw_data.get("response", {})
        cluster = response if isinstance(response, dict) else {}

        cluster_id = str(cluster.get("id", ""))
        name = cluster.get("name", "Rubrik Cluster")

        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Rubrik cluster: {name}",
                detail={
                    "cluster_id": cluster_id,
                    "name": name,
                    "version": cluster.get("version", ""),
                    "api_version": cluster.get("apiVersion", ""),
                    "node_count": cluster.get("nodeCount", 0),
                    "timezone": cluster.get("timezone", {}).get("timezone", ""),
                    "geolocation": cluster.get("geolocation", {}),
                },
                resource_id=cluster_id,
                resource_type="rubrik_cluster",
                resource_name=name,
                severity="info",
                confidence=1.0,
            )
        ]

    def _normalize_vms(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for vm in items:
            vm_id = str(vm.get("id", ""))
            name = vm.get("name", "unknown")
            sla_name = vm.get("effectiveSlaDomainName", vm.get("configuredSlaDomainName", ""))

            # VMs with no SLA are unprotected — high severity misconfiguration
            unprotected = sla_name in ("", "Unprotected", None)
            severity = "high" if unprotected else "info"
            obs_type = "misconfiguration" if unprotected else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Rubrik VM: {name}",
                    detail={
                        "vm_id": vm_id,
                        "name": name,
                        "sla_domain": sla_name,
                        "power_status": vm.get("powerStatus", ""),
                        "vcenter": vm.get("vcenterId", ""),
                        "is_replicated": vm.get("isReplicated", False),
                        "folder": vm.get("folderPath", []),
                    },
                    resource_id=vm_id,
                    resource_type="rubrik_vm",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sla_domains(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for sla in items:
            sla_id = str(sla.get("id", ""))
            name = sla.get("name", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rubrik SLA domain: {name}",
                    detail={
                        "sla_id": sla_id,
                        "name": name,
                        "frequencies": sla.get("frequencies", []),
                        "retention": sla.get("showAdvancedUi", False),
                        "allowed_backup_windows": sla.get("allowedBackupWindows", []),
                        "num_protected_objects": sla.get("numProtectedObjects", 0),
                    },
                    resource_id=sla_id,
                    resource_type="rubrik_sla_domain",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RubrikNormalizer())
