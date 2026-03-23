"""BigID normalizer — transforms raw BigID API responses into Findings.

Normalizes data catalog entries, policies, and scans as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BigIDNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for BigID data governance findings."""

    HANDLERS: dict[str, str] = {
        "bigid_data_catalog": "_normalize_data_catalog",
        "bigid_policies": "_normalize_policies",
        "bigid_scans": "_normalize_scans",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bigid" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "bigid",
            "source_type": SourceType.DATA_GOVERNANCE,
            "provider": "bigid",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_data_catalog(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("results", []))
        )

        for item in items:
            item_id = str(item.get("id", item.get("_id", "")))
            name = item.get("name", item.get("objectName", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"BigID data catalog: {name}",
                    detail={
                        "object_id": item_id,
                        "name": name,
                        "data_source": item.get("dataSourceName", ""),
                        "type": item.get("type", ""),
                        "sensitivity": item.get("sensitivityClassification", ""),
                        "pii_count": item.get("piiCount", 0),
                        "tags": item.get("tags", []),
                    },
                    resource_id=item_id,
                    resource_type="bigid_data_object",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("policies", []))
        )

        for policy in items:
            policy_id = str(policy.get("id", policy.get("_id", "")))
            name = policy.get("name", policy.get("policyName", "unknown"))
            is_active = policy.get("isActive", policy.get("enabled", True))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"BigID policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "type": policy.get("type", ""),
                        "is_active": is_active,
                        "description": policy.get("description", ""),
                        "frameworks": policy.get("frameworks", []),
                    },
                    resource_id=policy_id,
                    resource_type="bigid_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_scans(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("scans", []))
        )

        for scan in items:
            scan_id = str(scan.get("id", scan.get("_id", "")))
            name = scan.get("name", scan.get("scanName", "unknown"))
            status = scan.get("status", scan.get("state", "unknown"))
            severity = "high" if status in ("FAILED", "ERROR") else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"BigID scan: {name}",
                    detail={
                        "scan_id": scan_id,
                        "name": name,
                        "status": status,
                        "data_source": scan.get("dataSourceName", ""),
                        "started_at": scan.get("startedAt", ""),
                        "completed_at": scan.get("completedAt", ""),
                        "objects_scanned": scan.get("objectsScanned", 0),
                    },
                    resource_id=scan_id,
                    resource_type="bigid_scan",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BigIDNormalizer())
