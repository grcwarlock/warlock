"""Ivanti Patch Management normalizer — transforms raw Ivanti Patch API responses into Findings.

Normalizes machines and deployments (as inventory), and patches with missing
coverage (as vulnerability findings).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IvantiPatchNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Ivanti Patch Management."""

    HANDLERS: dict[str, str] = {
        "ivanti_patch_machines": "_normalize_machines",
        "ivanti_patch_patches": "_normalize_patches",
        "ivanti_patch_deployments": "_normalize_deployments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ivanti_patch" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ivanti_patch",
            "source_type": SourceType.MDM,
            "provider": "ivanti_patch",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_machines(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for machine in items:
            machine_id = str(machine.get("id", machine.get("machineId", "")))
            name = machine.get("name", machine.get("machineName", "unknown"))
            os = machine.get("os", machine.get("operatingSystem", ""))
            patch_status = machine.get("patchStatus", machine.get("complianceStatus", "unknown"))
            last_seen = machine.get("lastSeen", machine.get("lastContact", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ivanti Patch machine: {name}",
                    detail={
                        "machine_id": machine_id,
                        "name": name,
                        "os": os,
                        "patch_status": patch_status,
                        "last_seen": last_seen,
                        "ip_address": machine.get("ipAddress", ""),
                    },
                    resource_id=machine_id,
                    resource_type="ivanti_patch_machine",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_patches(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        _severity_map = {
            "critical": "critical",
            "important": "high",
            "moderate": "medium",
            "low": "low",
            "unspecified": "info",
        }

        for patch in items:
            patch_id = str(patch.get("id", patch.get("patchId", "")))
            name = patch.get("name", patch.get("title", "unknown"))
            severity_raw = str(patch.get("severity", "unspecified")).lower()
            is_missing = patch.get("isMissing", patch.get("missing", False))
            cve_ids = patch.get("cveIds", patch.get("cves", []))

            # Missing patches are vulnerabilities
            obs_type = "vulnerability" if is_missing else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Ivanti Patch {'missing patch' if is_missing else 'patch'}: {name}",
                    detail={
                        "patch_id": patch_id,
                        "name": name,
                        "severity": severity_raw,
                        "is_missing": is_missing,
                        "cve_ids": cve_ids,
                        "bulletin_id": patch.get("bulletinId", ""),
                        "release_date": patch.get("releaseDate", ""),
                    },
                    resource_id=patch_id,
                    resource_type="ivanti_patch_patch",
                    resource_name=name,
                    severity=_severity_map.get(severity_raw, "info"),
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_deployments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for deployment in items:
            dep_id = str(deployment.get("id", deployment.get("deploymentId", "")))
            name = deployment.get("name", deployment.get("deploymentName", "unknown"))
            status = deployment.get("status", "unknown")
            patch_count = deployment.get("patchCount", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ivanti Patch deployment: {name}",
                    detail={
                        "deployment_id": dep_id,
                        "name": name,
                        "status": status,
                        "patch_count": patch_count,
                        "created_date": deployment.get("createdDate", ""),
                        "completed_date": deployment.get("completedDate", ""),
                    },
                    resource_id=dep_id,
                    resource_type="ivanti_patch_deployment",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IvantiPatchNormalizer())
