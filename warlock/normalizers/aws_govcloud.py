"""AWS GovCloud normalizer — transforms raw AWS GovCloud API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AWSGovCloudNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for AWS GovCloud."""

    HANDLERS: dict[str, str] = {
        "govcloud_instances": "_normalize_govcloud_instances",
        "govcloud_vpcs": "_normalize_govcloud_vpcs",
        "govcloud_security_groups": "_normalize_govcloud_security_groups",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws_govcloud" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "aws_govcloud",
            "source_type": SourceType.CLOUD,
            "provider": "aws_govcloud",
            "observed_at": raw.observed_at,
        }

    def _normalize_govcloud_instances(self, raw: RawEventData) -> list[FindingData]:
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
                    title="AWS GovCloud govcloud instances: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="govcloud_instances",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_govcloud_vpcs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="AWS GovCloud govcloud vpcs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="govcloud_vpcs",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_govcloud_security_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="AWS GovCloud govcloud security groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="govcloud_security_groups",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AWSGovCloudNormalizer())
