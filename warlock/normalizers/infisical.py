"""Infisical normalizer — transforms raw Infisical API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class InfisicalNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Infisical."""

    HANDLERS: dict[str, str] = {
        "infisical_workspaces": "_normalize_infisical_workspaces",
        "infisical_secrets": "_normalize_infisical_secrets",
        "infisical_audit_logs": "_normalize_infisical_audit_logs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "infisical" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "infisical",
            "source_type": SourceType.IAM,
            "provider": "infisical",
            "observed_at": raw.observed_at,
        }

    def _normalize_infisical_workspaces(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infisical infisical workspaces: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infisical_workspaces",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_infisical_secrets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infisical infisical secrets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infisical_secrets",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_infisical_audit_logs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infisical infisical audit logs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infisical_audit_logs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(InfisicalNormalizer())
