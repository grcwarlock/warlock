"""ServiceNow ITAM normalizer — transforms raw ServiceNow ITAM API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ServiceNowITAMNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for ServiceNow ITAM."""

    HANDLERS: dict[str, str] = {
        "sn_itam_hardware": "_normalize_sn_itam_hardware",
        "sn_itam_licenses": "_normalize_sn_itam_licenses",
        "sn_itam_ci": "_normalize_sn_itam_ci",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "servicenow_itam" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "servicenow_itam",
            "source_type": SourceType.ITAM,
            "provider": "servicenow_itam",
            "observed_at": raw.observed_at,
        }

    def _normalize_sn_itam_hardware(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ServiceNow ITAM sn itam hardware: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sn_itam_hardware",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sn_itam_licenses(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ServiceNow ITAM sn itam licenses: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sn_itam_licenses",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sn_itam_ci(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ServiceNow ITAM sn itam ci: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sn_itam_ci",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ServiceNowITAMNormalizer())
