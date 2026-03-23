"""Twingate normalizer — transforms raw Twingate API responses into Findings.

Normalizes resources, connectors, and users as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TwingateNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Twingate findings."""

    HANDLERS: dict[str, str] = {
        "twingate_resources": "_normalize_resources",
        "twingate_connectors": "_normalize_connectors",
        "twingate_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "twingate" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "twingate",
            "source_type": SourceType.NETWORK,
            "provider": "twingate",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_resources(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("resources", response.get("data", []))

        for resource in items:
            resource_id = str(resource.get("id", ""))
            name = resource.get("name", resource.get("address", {}).get("value", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Twingate resource: {name}",
                    detail={
                        "resource_id": resource_id,
                        "name": name,
                        "address": resource.get("address", {}),
                        "protocols": resource.get("protocols", {}),
                        "groups": resource.get("groups", {}).get("edges", []),
                        "is_active": resource.get("isActive", True),
                    },
                    resource_id=resource_id,
                    resource_type="twingate_resource",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_connectors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("connectors", response.get("data", []))

        for connector in items:
            connector_id = str(connector.get("id", ""))
            name = connector.get("name", "unknown")
            state = connector.get("state", "ALIVE")

            severity = "high" if state not in ("ALIVE", "CONNECTED") else "info"
            obs_type = "misconfiguration" if state not in ("ALIVE", "CONNECTED") else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Twingate connector: {name}",
                    detail={
                        "connector_id": connector_id,
                        "name": name,
                        "state": state,
                        "remote_network": connector.get("remoteNetwork", {}).get("name", ""),
                        "version": connector.get("version", ""),
                    },
                    resource_id=connector_id,
                    resource_type="twingate_connector",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("users", response.get("data", []))

        for user in items:
            user_id = str(user.get("id", ""))
            email = user.get("email", "unknown")
            name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or email
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Twingate user: {name}",
                    detail={
                        "user_id": user_id,
                        "email": email,
                        "name": name,
                        "role": user.get("role", ""),
                        "state": user.get("state", ""),
                        "created_at": user.get("createdAt", ""),
                    },
                    resource_id=user_id,
                    resource_type="twingate_user",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TwingateNormalizer())
