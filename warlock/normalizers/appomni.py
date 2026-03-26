"""AppOmni normalizer — transforms raw AppOmni API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AppOmniNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for AppOmni."""

    HANDLERS: dict[str, str] = {
        "appomni_applications": "_normalize_appomni_applications",
        "appomni_alerts": "_normalize_appomni_alerts",
        "appomni_policies": "_normalize_appomni_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "appomni" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "appomni",
            "source_type": SourceType.SSPM,
            "provider": "appomni",
            "observed_at": raw.observed_at,
        }

    def _normalize_appomni_applications(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="AppOmni appomni applications: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="appomni_applications",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_appomni_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title="AppOmni appomni alerts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="appomni_alerts",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_appomni_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="AppOmni appomni policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="appomni_policies",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AppOmniNormalizer())
