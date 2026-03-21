"""Palo Alto Networks normalizer — transforms raw PAN-OS API responses into Findings.

Handles security rules, threat logs, traffic summaries, system info,
and GlobalProtect status.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PaloAltoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "pan_security_rules": "_normalize_security_rules",
        "pan_threat_logs": "_normalize_threat_logs",
        "pan_traffic_summary": "_normalize_traffic_summary",
        "pan_system_info": "_normalize_system_info",
        "pan_globalprotect": "_normalize_globalprotect",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "palo_alto" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Palo Alto findings."""
        return {
            "raw_event_id": raw.id,
            "source": "palo_alto",
            "source_type": SourceType.NETWORK,
            "provider": "palo_alto",
            "observed_at": raw.observed_at,
        }

    # -- Security Rules --

    def _normalize_security_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory security rules; flag disabled and overly permissive rules."""
        findings = []
        rules = raw.raw_data.get("rules", [])

        for rule in rules:
            rule_name = rule.get("@name", rule.get("name", ""))
            disabled = rule.get("disabled", "no")
            action = rule.get("action", "")
            source = rule.get("source", {})
            destination = rule.get("destination", {})
            application = rule.get("application", {})
            service = rule.get("service", {})

            # Normalize member lists
            src_members = self._get_members(source)
            dst_members = self._get_members(destination)
            app_members = self._get_members(application)
            svc_members = self._get_members(service)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Security rule: {rule_name} ({action})",
                    detail={
                        "rule_name": rule_name,
                        "action": action,
                        "disabled": disabled,
                        "source": src_members,
                        "destination": dst_members,
                        "application": app_members,
                        "service": svc_members,
                    },
                    resource_id=rule_name,
                    resource_type="palo_alto_security_rule",
                    resource_name=rule_name,
                    severity="info",
                )
            )

            # Flag disabled rules
            if disabled == "yes" or disabled is True:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Security rule disabled: {rule_name}",
                        detail={
                            "rule_name": rule_name,
                            "disabled": disabled,
                            "issue": "Security rule is disabled and not enforcing policy",
                        },
                        resource_id=rule_name,
                        resource_type="palo_alto_security_rule",
                        resource_name=rule_name,
                        severity="medium",
                    )
                )

            # Flag overly permissive "any" rules
            is_any_src = "any" in src_members
            is_any_dst = "any" in dst_members
            is_any_app = "any" in app_members
            is_any_svc = "any" in svc_members
            is_allow = action in ("allow", "")

            if is_allow and is_any_src and is_any_dst:
                severity = "critical" if is_any_app and is_any_svc else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Overly permissive rule: {rule_name} (any/any)",
                        detail={
                            "rule_name": rule_name,
                            "action": action,
                            "source": src_members,
                            "destination": dst_members,
                            "application": app_members,
                            "service": svc_members,
                            "issue": "Rule allows traffic from any source to any destination",
                        },
                        resource_id=rule_name,
                        resource_type="palo_alto_security_rule",
                        resource_name=rule_name,
                        severity=severity,
                    )
                )

        return findings

    @staticmethod
    def _get_members(field: dict | list | str) -> list[str]:
        """Extract member list from PAN-OS rule field."""
        if isinstance(field, str):
            return [field]
        if isinstance(field, list):
            return field
        if isinstance(field, dict):
            member = field.get("member", [])
            if isinstance(member, str):
                return [member]
            return member
        return []

    # -- Threat Logs --

    def _normalize_threat_logs(self, raw: RawEventData) -> list[FindingData]:
        """Flag threat detections from PAN-OS threat logs."""
        findings = []
        raw_response = raw.raw_data.get("raw_response", "")
        logs = raw.raw_data.get("logs", [])

        # If we have structured logs, process them
        for entry in logs:
            threat_name = entry.get("threatid", entry.get("threat_name", ""))
            severity_str = entry.get("severity", "medium").lower()
            src_ip = entry.get("src", entry.get("source_ip", ""))
            dst_ip = entry.get("dst", entry.get("destination_ip", ""))
            action = entry.get("action", "")
            category = entry.get("category", "")

            severity = (
                severity_str
                if severity_str in ("critical", "high", "medium", "low", "info")
                else "medium"
            )

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Threat detected: {threat_name}",
                    detail={
                        "threat_name": threat_name,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "action": action,
                        "category": category,
                        "original_severity": severity_str,
                    },
                    resource_id=f"{src_ip}->{dst_ip}",
                    resource_type="palo_alto_threat",
                    resource_name=str(threat_name),
                    severity=severity,
                )
            )

        # If only raw XML response and no structured logs, create inventory entry
        if raw_response and not logs:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title="PAN-OS threat logs collected (raw)",
                    detail={"raw_response_length": len(raw_response)},
                    resource_id="pan_threat_logs",
                    resource_type="palo_alto_threat_log",
                    resource_name="threat_logs",
                    severity="info",
                )
            )

        return findings

    # -- Traffic Summary --

    def _normalize_traffic_summary(self, raw: RawEventData) -> list[FindingData]:
        """Inventory traffic log collection."""
        findings = []
        raw_response = raw.raw_data.get("raw_response", "")
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="PAN-OS traffic logs collected",
                detail={"raw_response_length": len(raw_response)},
                resource_id="pan_traffic_summary",
                resource_type="palo_alto_traffic_log",
                resource_name="traffic_logs",
                severity="info",
            )
        )
        return findings

    # -- System Info --

    def _normalize_system_info(self, raw: RawEventData) -> list[FindingData]:
        """Inventory system information."""
        findings = []
        raw_response = raw.raw_data.get("raw_response", "")
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="PAN-OS system info collected",
                detail={"raw_response_length": len(raw_response)},
                resource_id="pan_system_info",
                resource_type="palo_alto_system",
                resource_name="system_info",
                severity="info",
            )
        )
        return findings

    # -- GlobalProtect --

    def _normalize_globalprotect(self, raw: RawEventData) -> list[FindingData]:
        """Inventory GlobalProtect status; flag disconnected users."""
        findings = []
        raw_response = raw.raw_data.get("raw_response", "")
        users = raw.raw_data.get("users", [])

        # Inventory
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="GlobalProtect status collected",
                detail={
                    "user_count": len(users),
                    "raw_response_length": len(raw_response),
                },
                resource_id="pan_globalprotect",
                resource_type="palo_alto_globalprotect",
                resource_name="globalprotect",
                severity="info",
            )
        )

        # Flag disconnected users if structured data available
        for user in users:
            username = user.get("username", "")
            status = user.get("status", "").lower()
            if status in ("disconnected", "inactive"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"GlobalProtect user disconnected: {username}",
                        detail={
                            "username": username,
                            "status": status,
                            "issue": "User is disconnected from GlobalProtect VPN",
                        },
                        resource_id=username,
                        resource_type="palo_alto_globalprotect_user",
                        resource_name=username,
                        severity="low",
                    )
                )

        return findings


# Register
registry.register(PaloAltoNormalizer())
