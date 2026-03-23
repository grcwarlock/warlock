"""Druva normalizer — transforms raw Druva inSync API responses into Findings.

Normalizes endpoints and backup sets as inventory findings,
restores as inventory, backup failures as misconfiguration.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_FAILED_STATUSES = {"failed", "error", "Failed", "Error", "FAILED", "ERROR"}


class DruvaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Druva backup findings."""

    HANDLERS: dict[str, str] = {
        "druva_endpoints": "_normalize_endpoints",
        "druva_backupsets": "_normalize_backupsets",
        "druva_restores": "_normalize_restores",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "druva" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "druva",
            "source_type": SourceType.BACKUP,
            "provider": "druva",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_endpoints(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("endpoints", response.get("data", []))
        )

        for endpoint in items:
            endpoint_id = str(endpoint.get("id", endpoint.get("endpointId", "")))
            name = endpoint.get("name", endpoint.get("deviceName", "unknown"))
            status = endpoint.get("status", endpoint.get("backupStatus", "unknown"))

            is_failed = status in _FAILED_STATUSES
            severity = "high" if is_failed else "info"
            obs_type = "misconfiguration" if is_failed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Druva endpoint: {name}",
                    detail={
                        "endpoint_id": endpoint_id,
                        "name": name,
                        "os": endpoint.get("os", endpoint.get("operatingSystem", "")),
                        "status": status,
                        "user_email": endpoint.get("userEmail", ""),
                        "last_backup": endpoint.get("lastBackupTime", ""),
                    },
                    resource_id=endpoint_id,
                    resource_type="druva_endpoint",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_backupsets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("backupsets", response.get("data", []))
        )

        for bset in items:
            bset_id = str(bset.get("id", bset.get("backupSetId", "")))
            name = bset.get("name", bset.get("backupSetName", "unknown"))
            status = bset.get("status", "unknown")

            is_failed = status in _FAILED_STATUSES
            severity = "high" if is_failed else "info"
            obs_type = "misconfiguration" if is_failed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Druva backup set: {name}",
                    detail={
                        "backupset_id": bset_id,
                        "name": name,
                        "status": status,
                        "endpoint_id": str(bset.get("endpointId", "")),
                        "size_bytes": bset.get("sizeBytes", 0),
                        "last_backup": bset.get("lastBackupTime", ""),
                    },
                    resource_id=bset_id,
                    resource_type="druva_backupset",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_restores(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("restores", response.get("data", []))
        )

        for restore in items:
            restore_id = str(restore.get("id", restore.get("restoreId", "")))
            name = restore.get("name", restore.get("restoreName", "Restore"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Druva restore: {name}",
                    detail={
                        "restore_id": restore_id,
                        "name": name,
                        "status": restore.get("status", ""),
                        "requested_by": restore.get("requestedBy", ""),
                        "target": restore.get("target", ""),
                        "started_at": restore.get("startedAt", ""),
                        "completed_at": restore.get("completedAt", ""),
                    },
                    resource_id=restore_id,
                    resource_type="druva_restore",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DruvaNormalizer())
