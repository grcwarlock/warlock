"""Archer GRC normalizer — transforms raw RSA Archer API responses into Findings.

Normalizes content records and application definitions as inventory findings.
Content records that map to risk or issue records are surfaced as policy_violation.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Application names that indicate risk/issue content worth escalating
_RISK_APP_KEYWORDS = frozenset({"risk", "issue", "finding", "incident", "audit", "exception"})


class ArcherNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "archer_content": "_normalize_content",
        "archer_applications": "_normalize_applications",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "archer" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "archer",
            "source_type": SourceType.GRC,
            "provider": "archer",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_content(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for record in items:
            # Archer content records have a complex field structure
            record_id = str(record.get("Id", record.get("id", record.get("ContentId", ""))))
            content_name = record.get("Name", record.get("name", f"Record {record_id}"))
            app_name = str(
                record.get("LevelName", record.get("ApplicationName", record.get("ModuleName", "")))
            ).lower()
            tracking_id = str(record.get("TrackingId", record.get("trackingId", "")))

            # Determine if this is risk-related content
            is_risk = any(kw in app_name for kw in _RISK_APP_KEYWORDS)
            obs_type = "policy_violation" if is_risk else "inventory"
            severity = "medium" if is_risk else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Archer record: {content_name}",
                    detail={
                        "record_id": record_id,
                        "content_name": content_name,
                        "tracking_id": tracking_id,
                        "application_name": app_name,
                        "level_id": str(record.get("LevelId", "")),
                        "last_updated": record.get("LastUpdated", record.get("ModifiedDate", "")),
                    },
                    resource_id=record_id,
                    resource_type="archer_content_record",
                    resource_name=content_name,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings

    def _normalize_applications(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for app in items:
            app_id = str(app.get("Id", app.get("id", app.get("AppId", ""))))
            name = app.get("Name", app.get("name", "unknown"))
            guid = app.get("Guid", app.get("guid", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Archer application: {name}",
                    detail={
                        "app_id": app_id,
                        "name": name,
                        "guid": guid,
                        "alias": app.get("Alias", app.get("alias", "")),
                        "status": app.get("Status", app.get("status", "")),
                        "level_count": app.get("LevelCount", 0),
                    },
                    resource_id=app_id,
                    resource_type="archer_application",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ArcherNormalizer())
