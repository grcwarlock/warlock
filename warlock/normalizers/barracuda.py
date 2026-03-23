"""Barracuda normalizer — transforms raw Barracuda API responses into Findings.

Normalizes firewalls and policies (as inventory), and threats (as alert).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BarracudaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Barracuda Networks."""

    HANDLERS: dict[str, str] = {
        "barracuda_firewalls": "_normalize_firewalls",
        "barracuda_threats": "_normalize_threats",
        "barracuda_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "barracuda" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "barracuda",
            "source_type": SourceType.NETWORK,
            "provider": "barracuda",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_firewalls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for fw in items:
            fw_id = str(fw.get("id", ""))
            name = fw.get("name", "unknown")
            status = fw.get("status", "unknown")
            model = fw.get("model", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Barracuda firewall: {name}",
                    detail={
                        "firewall_id": fw_id,
                        "name": name,
                        "status": status,
                        "model": model,
                        "firmware_version": fw.get("firmware_version", ""),
                        "ip_address": fw.get("ip_address", ""),
                    },
                    resource_id=fw_id,
                    resource_type="barracuda_firewall",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_threats(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        _severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        for threat in items:
            threat_id = str(threat.get("id", ""))
            name = threat.get("name", threat.get("threat_name", "unknown"))
            severity_raw = str(threat.get("severity", "info")).lower()

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Barracuda threat: {name}",
                    detail={
                        "threat_id": threat_id,
                        "name": name,
                        "severity": severity_raw,
                        "source_ip": threat.get("source_ip", ""),
                        "destination_ip": threat.get("destination_ip", ""),
                        "action": threat.get("action", ""),
                        "timestamp": threat.get("timestamp", ""),
                    },
                    resource_id=threat_id,
                    resource_type="barracuda_threat",
                    resource_name=name,
                    severity=_severity_map.get(severity_raw, "medium"),
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            policy_type = policy.get("type", "")
            enabled = policy.get("enabled", True)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Barracuda policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "type": policy_type,
                        "enabled": enabled,
                        "description": policy.get("description", ""),
                    },
                    resource_id=policy_id,
                    resource_type="barracuda_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BarracudaNormalizer())
