"""HashiCorp Boundary normalizer — transforms raw HashiCorp Boundary API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BoundaryNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for HashiCorp Boundary."""

    HANDLERS: dict[str, str] = {
        "boundary_scopes": "_normalize_boundary_scopes",
        "boundary_targets": "_normalize_boundary_targets",
        "boundary_sessions": "_normalize_boundary_sessions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "boundary" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "boundary",
            "source_type": SourceType.IAM,
            "provider": "boundary",
            "observed_at": raw.observed_at,
        }

    def _normalize_boundary_scopes(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HashiCorp Boundary boundary scopes: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="boundary_scopes",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_boundary_targets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HashiCorp Boundary boundary targets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="boundary_targets",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_boundary_sessions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HashiCorp Boundary boundary sessions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="boundary_sessions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BoundaryNormalizer())
