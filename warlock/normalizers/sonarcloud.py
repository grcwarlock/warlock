"""SonarCloud normalizer — transforms raw SonarCloud API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SonarCloudNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for SonarCloud."""

    HANDLERS: dict[str, str] = {
        "sonarcloud_projects": "_normalize_sonarcloud_projects",
        "sonarcloud_issues": "_normalize_sonarcloud_issues",
        "sonarcloud_measures": "_normalize_sonarcloud_measures",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sonarcloud" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sonarcloud",
            "source_type": SourceType.CODE,
            "provider": "sonarcloud",
            "observed_at": raw.observed_at,
        }

    def _normalize_sonarcloud_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SonarCloud sonarcloud projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sonarcloud_projects",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sonarcloud_issues(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SonarCloud sonarcloud issues: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sonarcloud_issues",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sonarcloud_measures(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SonarCloud sonarcloud measures: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sonarcloud_measures",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SonarCloudNormalizer())
