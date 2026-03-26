"""Supabase normalizer — transforms raw Supabase API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SupabaseNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Supabase."""

    HANDLERS: dict[str, str] = {
        "supabase_projects": "_normalize_supabase_projects",
        "supabase_organizations": "_normalize_supabase_organizations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "supabase" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "supabase",
            "source_type": SourceType.CLOUD,
            "provider": "supabase",
            "observed_at": raw.observed_at,
        }

    def _normalize_supabase_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Supabase supabase projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="supabase_projects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_supabase_organizations(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Supabase supabase organizations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="supabase_organizations",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SupabaseNormalizer())
