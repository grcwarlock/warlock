"""Render normalizer — transforms raw Render API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RenderNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Render."""

    HANDLERS: dict[str, str] = {
        "render_services": "_normalize_render_services",
        "render_deploys": "_normalize_render_deploys",
        "render_env_groups": "_normalize_render_env_groups",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "render" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "render",
            "source_type": SourceType.CLOUD,
            "provider": "render",
            "observed_at": raw.observed_at,
        }

    def _normalize_render_services(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Render render services: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="render_services",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_render_deploys(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Render render deploys: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="render_deploys",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_render_env_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Render render env groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="render_env_groups",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RenderNormalizer())
