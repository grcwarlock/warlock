"""F5 BIG-IP normalizer — transforms raw F5 iControl REST API responses into Findings.

Normalizes virtual servers and firewall policies (as inventory), and
performance stats (as inventory).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class F5Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for F5 BIG-IP."""

    HANDLERS: dict[str, str] = {
        "f5_virtual_servers": "_normalize_virtual_servers",
        "f5_performance": "_normalize_performance",
        "f5_firewall_policies": "_normalize_firewall_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "f5" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "f5",
            "source_type": SourceType.NETWORK,
            "provider": "f5",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_virtual_servers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for vs in items:
            vs_name = vs.get("name", "unknown")
            vs_full_path = vs.get("fullPath", vs_name)
            destination = vs.get("destination", "")
            enabled_state = vs.get("enabled", True)
            partition = vs.get("partition", "Common")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"F5 virtual server: {vs_name}",
                    detail={
                        "name": vs_name,
                        "full_path": vs_full_path,
                        "destination": destination,
                        "partition": partition,
                        "enabled": enabled_state,
                        "pool": vs.get("pool", ""),
                        "ip_protocol": vs.get("ipProtocol", ""),
                    },
                    resource_id=vs_full_path,
                    resource_type="f5_virtual_server",
                    resource_name=vs_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_performance(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for perf in items:
            name = perf.get("name", "all-stats")
            entries = perf.get("entries", {})

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"F5 performance stats: {name}",
                    detail={
                        "name": name,
                        "entries_count": len(entries),
                        "kind": perf.get("kind", ""),
                    },
                    resource_id=name,
                    resource_type="f5_performance",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_firewall_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_name = policy.get("name", "unknown")
            full_path = policy.get("fullPath", policy_name)
            partition = policy.get("partition", "Common")
            rules = policy.get("rulesReference", {})
            rule_count = rules.get("totalItems", 0) if isinstance(rules, dict) else 0

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"F5 firewall policy: {policy_name}",
                    detail={
                        "name": policy_name,
                        "full_path": full_path,
                        "partition": partition,
                        "rule_count": rule_count,
                        "description": policy.get("description", ""),
                    },
                    resource_id=full_path,
                    resource_type="f5_firewall_policy",
                    resource_name=policy_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(F5Normalizer())
