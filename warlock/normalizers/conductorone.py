"""ConductorOne normalizer — transforms raw ConductorOne API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ConductorOneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for ConductorOne."""

    HANDLERS: dict[str, str] = {
        "conductorone_apps": "_normalize_conductorone_apps",
        "conductorone_users": "_normalize_conductorone_users",
        "conductorone_entitlements": "_normalize_conductorone_entitlements",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "conductorone" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "conductorone",
            "source_type": SourceType.IAM,
            "provider": "conductorone",
            "observed_at": raw.observed_at,
        }

    def _normalize_conductorone_apps(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="inventory",
                    title="ConductorOne conductorone apps: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="conductorone_apps",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_conductorone_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ConductorOne conductorone users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="conductorone_users",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_conductorone_entitlements(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="inventory",
                    title="ConductorOne conductorone entitlements: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="conductorone_entitlements",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ConductorOneNormalizer())
