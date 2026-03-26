"""Akamai normalizer — transforms raw Akamai API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AkamaiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Akamai."""

    HANDLERS: dict[str, str] = {
        "akamai_security_configs": "_normalize_akamai_security_configs",
        "akamai_firewall_rules": "_normalize_akamai_firewall_rules",
        "akamai_events": "_normalize_akamai_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "akamai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "akamai",
            "source_type": SourceType.NETWORK,
            "provider": "akamai",
            "observed_at": raw.observed_at,
        }

    def _normalize_akamai_security_configs(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Akamai akamai security configs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="akamai_security_configs",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_akamai_firewall_rules(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Akamai akamai firewall rules: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="akamai_firewall_rules",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_akamai_events(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Akamai akamai events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="akamai_events",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AkamaiNormalizer())
