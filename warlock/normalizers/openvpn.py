"""OpenVPN normalizer — transforms raw OpenVPN API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OpenVPNNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for OpenVPN."""

    HANDLERS: dict[str, str] = {
        "openvpn_networks": "_normalize_openvpn_networks",
        "openvpn_connectors": "_normalize_openvpn_connectors",
        "openvpn_users": "_normalize_openvpn_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "openvpn" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "openvpn",
            "source_type": SourceType.NETWORK,
            "provider": "openvpn",
            "observed_at": raw.observed_at,
        }

    def _normalize_openvpn_networks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenVPN openvpn networks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openvpn_networks",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_openvpn_connectors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenVPN openvpn connectors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openvpn_connectors",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_openvpn_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenVPN openvpn users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openvpn_users",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OpenVPNNormalizer())
