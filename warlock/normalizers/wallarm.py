"""Wallarm normalizer — transforms raw Wallarm API responses into Findings.

Normalizes attacks as alerts, vulnerabilities as vulnerability findings,
and rules as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_WALLARM_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}

# Wallarm attack types mapped to human-readable strings
_ATTACK_TYPE_MAP: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "rce": "Remote Code Execution",
    "xxe": "XML External Entity",
    "ptrav": "Path Traversal",
    "crlf": "CRLF Injection",
    "nosqli": "NoSQL Injection",
    "ldapi": "LDAP Injection",
    "scanner": "Scanner Activity",
}


class WallarmNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Wallarm telemetry."""

    HANDLERS: dict[str, str] = {
        "wallarm_attacks": "_normalize_attacks",
        "wallarm_vulns": "_normalize_vulns",
        "wallarm_rules": "_normalize_rules",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "wallarm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "wallarm",
            "source_type": SourceType.NETWORK,
            "provider": "wallarm",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_attacks(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for attack in raw.raw_data.get("response", []):
            attack_id = str(attack.get("id", ""))
            attack_type = attack.get("type", "")
            attack_label = _ATTACK_TYPE_MAP.get(attack_type, attack_type)
            target = attack.get("domain", attack.get("path", ""))
            # Wallarm attacks do not carry a severity field directly;
            # derive from attack type or default to high for active attacks.
            severity = "high"
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Wallarm attack: {attack_label} on {target}",
                    detail={
                        "attack_id": attack_id,
                        "type": attack_type,
                        "label": attack_label,
                        "target": target,
                        "source_ip": attack.get("ip", ""),
                        "hits": attack.get("hits", 0),
                        "time": attack.get("time", ""),
                        "blocked": attack.get("blocked", False),
                    },
                    resource_id=attack_id,
                    resource_type="wallarm_attack",
                    resource_name=f"{attack_label}/{target}",
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_vulns(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vuln in raw.raw_data.get("response", []):
            vuln_id = str(vuln.get("id", ""))
            vuln_type = vuln.get("type", "")
            raw_severity = vuln.get("threat", vuln.get("severity", "medium"))
            # Wallarm uses numeric threat (0-100) or string severity
            if isinstance(raw_severity, int):
                if raw_severity >= 80:
                    severity = "critical"
                elif raw_severity >= 60:
                    severity = "high"
                elif raw_severity >= 30:
                    severity = "medium"
                else:
                    severity = "low"
            else:
                severity = _WALLARM_SEVERITY.get(str(raw_severity).lower(), "medium")
            target = vuln.get("domain", vuln.get("url", ""))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Wallarm vulnerability: {vuln_type} on {target}",
                    detail={
                        "vuln_id": vuln_id,
                        "type": vuln_type,
                        "target": target,
                        "threat": raw_severity,
                        "parameter": vuln.get("parameter", ""),
                        "status": vuln.get("status", ""),
                        "discovered_at": vuln.get("discoveredAt", ""),
                    },
                    resource_id=vuln_id,
                    resource_type="wallarm_vulnerability",
                    resource_name=f"{vuln_type}/{target}",
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_rules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for rule in raw.raw_data.get("response", []):
            rule_id = str(rule.get("id", ""))
            rule_type = rule.get("type", "rule")
            action = rule.get("action", {})
            action_type = action.get("type", "") if isinstance(action, dict) else str(action)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Wallarm rule: {rule_type} ({action_type})",
                    detail={
                        "rule_id": rule_id,
                        "type": rule_type,
                        "action": action_type,
                        "enabled": rule.get("enabled", True),
                        "created_at": rule.get("createdAt", ""),
                        "updated_at": rule.get("updatedAt", ""),
                        "comment": rule.get("comment", ""),
                    },
                    resource_id=rule_id,
                    resource_type="wallarm_rule",
                    resource_name=f"{rule_type}/{rule_id}",
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(WallarmNormalizer())
