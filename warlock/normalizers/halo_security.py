"""Halo Security normalizer — transforms raw Halo Security API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HaloSecurityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Halo Security."""

    HANDLERS: dict[str, str] = {
        "halo_assets": "_normalize_halo_assets",
        "halo_vulnerabilities": "_normalize_halo_vulnerabilities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "halo_security" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "halo_security",
            "source_type": SourceType.SCANNER,
            "provider": "halo_security",
            "observed_at": raw.observed_at,
        }

    def _normalize_halo_assets(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Halo Security halo assets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="halo_assets",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_halo_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Halo Security halo vulnerabilities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="halo_vulnerabilities",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HaloSecurityNormalizer())
