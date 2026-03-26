"""PingOne normalizer — transforms raw PingOne API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PingIdentityNewNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for PingOne."""

    HANDLERS: dict[str, str] = {
        "pingone_users": "_normalize_pingone_users",
        "pingone_groups": "_normalize_pingone_groups",
        "pingone_signon_policies": "_normalize_pingone_signon_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ping_identity_new" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ping_identity_new",
            "source_type": SourceType.IAM,
            "provider": "ping_identity_new",
            "observed_at": raw.observed_at,
        }

    def _normalize_pingone_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="PingOne pingone users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pingone_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_pingone_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="PingOne pingone groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pingone_groups",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_pingone_signon_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="PingOne pingone signon policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pingone_signon_policies",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PingIdentityNewNormalizer())
