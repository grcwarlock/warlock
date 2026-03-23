"""Ivanti Patch normalizer — transforms raw Ivanti API responses into Findings.

Normalizes machines (as inventory), patches (as vulnerability when missing,
inventory when applied), and deployments (as inventory).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Ivanti severity strings → normalized severity
_IVANTI_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class IvantiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ivanti_machines": "_normalize_machines",
        "ivanti_patches": "_normalize_patches",
        "ivanti_deployments": "_normalize_deployments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ivanti" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ivanti",
            "source_type": SourceType.MDM,
            "provider": "ivanti",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Machines --

    def _normalize_machines(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for machine in items:
            machine_id = str(machine.get("id", machine.get("machineId", "")))
            hostname = machine.get("hostname", machine.get("name", "unknown"))
            os_name = machine.get("os", machine.get("operatingSystem", "unknown"))
            ip_address = machine.get("ipAddress", machine.get("ip", ""))
            status = machine.get("status", machine.get("patchStatus", "unknown"))
            last_seen = machine.get("lastSeen", machine.get("lastContact", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ivanti managed machine: {hostname}",
                    detail={
                        "machine_id": machine_id,
                        "hostname": hostname,
                        "os": os_name,
                        "ip_address": ip_address,
                        "status": status,
                        "last_seen": last_seen,
                    },
                    resource_id=machine_id,
                    resource_type="ivanti_machine",
                    resource_name=hostname,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Patches --

    def _normalize_patches(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for patch in items:
            patch_id = str(patch.get("id", patch.get("patchId", "")))
            title = patch.get("title", patch.get("name", "unknown patch"))
            severity_raw = str(patch.get("severity", "low")).lower()
            severity = _IVANTI_SEVERITY_MAP.get(severity_raw, "low")
            is_missing = patch.get("isMissing", patch.get("missing", False))
            kb_article = patch.get("kbArticle", patch.get("kb", ""))
            cve_ids = patch.get("cveIds", patch.get("cves", []))
            release_date = patch.get("releaseDate", "")

            if is_missing:
                obs_type = "vulnerability"
                finding_title = f"Ivanti missing patch: {title}"
            else:
                obs_type = "inventory"
                finding_title = f"Ivanti patch applied: {title}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=finding_title,
                    detail={
                        "patch_id": patch_id,
                        "title": title,
                        "severity": severity_raw,
                        "is_missing": is_missing,
                        "kb_article": kb_article,
                        "cve_ids": cve_ids if isinstance(cve_ids, list) else [cve_ids],
                        "release_date": release_date,
                    },
                    resource_id=patch_id,
                    resource_type="ivanti_patch",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Deployments --

    def _normalize_deployments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for deployment in items:
            deployment_id = str(deployment.get("id", deployment.get("deploymentId", "")))
            name = deployment.get("name", deployment.get("description", "unknown"))
            status = deployment.get("status", "unknown")
            start_date = deployment.get("startDate", "")
            end_date = deployment.get("endDate", "")
            target_count = deployment.get("targetCount", 0)
            success_count = deployment.get("successCount", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ivanti deployment: {name}",
                    detail={
                        "deployment_id": deployment_id,
                        "name": name,
                        "status": status,
                        "start_date": start_date,
                        "end_date": end_date,
                        "target_count": target_count,
                        "success_count": success_count,
                    },
                    resource_id=deployment_id,
                    resource_type="ivanti_deployment",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IvantiNormalizer())
