"""Oracle HCM normalizer — transforms raw Oracle HCM API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OracleHCMNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Oracle HCM."""

    HANDLERS: dict[str, str] = {
        "oracle_hcm_workers": "_normalize_oracle_hcm_workers",
        "oracle_hcm_departments": "_normalize_oracle_hcm_departments",
        "oracle_hcm_absences": "_normalize_oracle_hcm_absences",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "oracle_hcm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "oracle_hcm",
            "source_type": SourceType.HRIS,
            "provider": "oracle_hcm",
            "observed_at": raw.observed_at,
        }

    def _normalize_oracle_hcm_workers(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Oracle HCM oracle hcm workers: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="oracle_hcm_workers",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_oracle_hcm_departments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Oracle HCM oracle hcm departments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="oracle_hcm_departments",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_oracle_hcm_absences(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Oracle HCM oracle hcm absences: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="oracle_hcm_absences",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OracleHCMNormalizer())
