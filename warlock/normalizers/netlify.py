"""Netlify normalizer — transforms raw Netlify API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class NetlifyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Netlify."""

    HANDLERS: dict[str, str] = {
        "netlify_sites": "_normalize_netlify_sites",
        "netlify_deploys": "_normalize_netlify_deploys",
        "netlify_accounts": "_normalize_netlify_accounts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "netlify" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "netlify",
            "source_type": SourceType.CLOUD,
            "provider": "netlify",
            "observed_at": raw.observed_at,
        }

    def _normalize_netlify_sites(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Netlify netlify sites: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netlify_sites",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_netlify_deploys(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Netlify netlify deploys: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netlify_deploys",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_netlify_accounts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Netlify netlify accounts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netlify_accounts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(NetlifyNormalizer())
