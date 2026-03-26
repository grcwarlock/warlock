"""Argo CD normalizer — transforms raw Argo CD API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ArgoCDNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Argo CD."""

    HANDLERS: dict[str, str] = {
        "argocd_applications": "_normalize_argocd_applications",
        "argocd_clusters": "_normalize_argocd_clusters",
        "argocd_repositories": "_normalize_argocd_repositories",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "argocd" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "argocd",
            "source_type": SourceType.CI_CD,
            "provider": "argocd",
            "observed_at": raw.observed_at,
        }

    def _normalize_argocd_applications(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Argo CD argocd applications: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="argocd_applications",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_argocd_clusters(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Argo CD argocd clusters: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="argocd_clusters",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_argocd_repositories(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Argo CD argocd repositories: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="argocd_repositories",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ArgoCDNormalizer())
