"""LaunchDarkly normalizer — transforms raw LaunchDarkly API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LaunchDarklyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for LaunchDarkly."""

    HANDLERS: dict[str, str] = {
        "launchdarkly_flags": "_normalize_launchdarkly_flags",
        "launchdarkly_audit_log": "_normalize_launchdarkly_audit_log",
        "launchdarkly_members": "_normalize_launchdarkly_members",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "launchdarkly" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "launchdarkly",
            "source_type": SourceType.CI_CD,
            "provider": "launchdarkly",
            "observed_at": raw.observed_at,
        }

    def _normalize_launchdarkly_flags(self, raw: RawEventData) -> list[FindingData]:
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
                    title="LaunchDarkly launchdarkly flags: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="launchdarkly_flags",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_launchdarkly_audit_log(self, raw: RawEventData) -> list[FindingData]:
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
                    title="LaunchDarkly launchdarkly audit log: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="launchdarkly_audit_log",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_launchdarkly_members(self, raw: RawEventData) -> list[FindingData]:
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
                    title="LaunchDarkly launchdarkly members: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="launchdarkly_members",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LaunchDarklyNormalizer())
