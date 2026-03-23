"""Linode normalizer — transforms raw Linode API responses into Findings.

Normalizes instances and firewalls (as inventory), and account events (as alert).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LinodeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Linode/Akamai Cloud."""

    HANDLERS: dict[str, str] = {
        "linode_instances": "_normalize_instances",
        "linode_firewalls": "_normalize_firewalls",
        "linode_events": "_normalize_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "linode" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "linode",
            "source_type": SourceType.CLOUD,
            "provider": "linode",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_instances(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for instance in items:
            instance_id = str(instance.get("id", ""))
            label = instance.get("label", "unknown")
            status = instance.get("status", "unknown")
            region = instance.get("region", "")
            ltype = instance.get("type", "")
            ipv4 = instance.get("ipv4", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Linode instance: {label}",
                    detail={
                        "instance_id": instance_id,
                        "label": label,
                        "status": status,
                        "type": ltype,
                        "ipv4": ipv4,
                        "created": instance.get("created", ""),
                    },
                    resource_id=instance_id,
                    resource_type="linode_instance",
                    resource_name=label,
                    region=region,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_firewalls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for firewall in items:
            fw_id = str(firewall.get("id", ""))
            label = firewall.get("label", "unknown")
            status = firewall.get("status", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Linode firewall: {label}",
                    detail={
                        "firewall_id": fw_id,
                        "label": label,
                        "status": status,
                        "created": firewall.get("created", ""),
                        "updated": firewall.get("updated", ""),
                    },
                    resource_id=fw_id,
                    resource_type="linode_firewall",
                    resource_name=label,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        _severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "notification": "info",
        }

        for event in items:
            event_id = str(event.get("id", ""))
            action = event.get("action", "unknown")
            entity = event.get("entity", {}) or {}
            entity_label = entity.get("label", "") if isinstance(entity, dict) else ""
            entity_id = str(entity.get("id", "")) if isinstance(entity, dict) else ""

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Linode event: {action}",
                    detail={
                        "event_id": event_id,
                        "action": action,
                        "entity_label": entity_label,
                        "entity_id": entity_id,
                        "status": event.get("status", ""),
                        "created": event.get("created", ""),
                        "username": event.get("username", ""),
                    },
                    resource_id=entity_id,
                    resource_type="linode_event",
                    resource_name=entity_label,
                    severity=_severity_map.get(event.get("severity", ""), "info"),
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LinodeNormalizer())
