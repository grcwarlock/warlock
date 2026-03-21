"""Sophos normalizer — transforms raw Sophos Central API responses into Findings.

Handles endpoints (health, protection, tamper protection), alerts (threats,
policy violations), and firewall groups/rules. Flags unhealthy endpoints,
tamper protection disabled, unresolved malware, stale endpoints, and
outdated definitions.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Endpoints not seen in this many days are flagged
_STALE_ENDPOINT_DAYS = 7


class SophosNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sophos_endpoints": "_normalize_endpoints",
        "sophos_alerts": "_normalize_alerts",
        "sophos_firewall_groups": "_normalize_firewall_groups",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sophos" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Sophos findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sophos",
            "source_type": SourceType.EDR,
            "provider": "sophos",
            "observed_at": raw.observed_at,
        }

    # -- Endpoints --

    def _normalize_endpoints(self, raw: RawEventData) -> list[FindingData]:
        """Inventory endpoints; flag health issues, tamper protection, stale agents."""
        findings = []
        endpoints = raw.raw_data.get("endpoints", [])
        now = datetime.now(timezone.utc)

        for ep in endpoints:
            ep_id = ep.get("id", "")
            hostname = ep.get("hostname", "")
            ep_type = ep.get("type", "")
            os_info = ep.get("os", {})
            os_name = os_info.get("name", "") if isinstance(os_info, dict) else ""
            os_platform = os_info.get("platform", "") if isinstance(os_info, dict) else ""

            health = ep.get("health", {})
            overall_health = health.get("overall", "") if isinstance(health, dict) else ""
            threats_status = (
                health.get("threats", {}).get("status", "") if isinstance(health, dict) else ""
            )
            services_status = (
                health.get("services", {}).get("status", "") if isinstance(health, dict) else ""
            )

            tamper = ep.get("tamperProtectionEnabled", True)
            last_seen = ep.get("lastSeenAt", "")

            assigned_products = ep.get("assignedProducts", [])
            ep.get("lockdown", {})

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Endpoint: {hostname} ({os_platform})",
                    detail={
                        "endpoint_id": ep_id,
                        "hostname": hostname,
                        "type": ep_type,
                        "os_name": os_name,
                        "os_platform": os_platform,
                        "overall_health": overall_health,
                        "tamper_protection": tamper,
                        "last_seen": last_seen,
                        "assigned_products": [p.get("code", "") for p in assigned_products]
                        if isinstance(assigned_products, list)
                        else [],
                    },
                    resource_id=ep_id,
                    resource_type="sophos_endpoint",
                    resource_name=hostname,
                    severity="info",
                )
            )

            # Flag endpoints with bad health
            if overall_health and overall_health.lower() not in ("good", ""):
                severity = "high" if overall_health.lower() == "bad" else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Endpoint unhealthy: {hostname} ({overall_health})",
                        detail={
                            "endpoint_id": ep_id,
                            "hostname": hostname,
                            "overall_health": overall_health,
                            "threats_status": threats_status,
                            "services_status": services_status,
                            "issue": f"Endpoint health is '{overall_health}' — "
                            f"protection may be degraded",
                        },
                        resource_id=ep_id,
                        resource_type="sophos_endpoint",
                        resource_name=hostname,
                        severity=severity,
                    )
                )

            # Flag tamper protection disabled
            if not tamper:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Tamper protection disabled: {hostname}",
                        detail={
                            "endpoint_id": ep_id,
                            "hostname": hostname,
                            "tamper_protection": False,
                            "issue": "Tamper protection is disabled — endpoint agent "
                            "can be uninstalled or modified by attackers",
                        },
                        resource_id=ep_id,
                        resource_type="sophos_endpoint",
                        resource_name=hostname,
                        severity="high",
                    )
                )

            # Flag endpoints not seen in > 7 days
            if last_seen:
                try:
                    # Sophos uses ISO 8601 format
                    seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    days_since = (now - seen_dt).days
                    if days_since > _STALE_ENDPOINT_DAYS:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="misconfiguration",
                                title=f"Stale endpoint: {hostname} ({days_since}d unseen)",
                                detail={
                                    "endpoint_id": ep_id,
                                    "hostname": hostname,
                                    "last_seen": last_seen,
                                    "days_since_seen": days_since,
                                    "threshold_days": _STALE_ENDPOINT_DAYS,
                                    "issue": f"Endpoint has not checked in for "
                                    f"{days_since} days — may be offline, "
                                    f"decommissioned, or compromised",
                                },
                                resource_id=ep_id,
                                resource_type="sophos_endpoint",
                                resource_name=hostname,
                                severity="medium",
                            )
                        )
                except (ValueError, TypeError):
                    pass

            # Flag outdated definitions
            for product in assigned_products or []:
                if isinstance(product, dict):
                    prod_status = product.get("status", "")
                    prod_code = product.get("code", "")
                    if prod_status and prod_status.lower() not in ("installed", ""):
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="misconfiguration",
                                title=f"Product issue on {hostname}: {prod_code} ({prod_status})",
                                detail={
                                    "endpoint_id": ep_id,
                                    "hostname": hostname,
                                    "product_code": prod_code,
                                    "product_status": prod_status,
                                    "issue": f"Protection product '{prod_code}' is in "
                                    f"'{prod_status}' state — definitions may "
                                    f"be outdated or installation incomplete",
                                },
                                resource_id=ep_id,
                                resource_type="sophos_endpoint",
                                resource_name=hostname,
                                severity="medium",
                            )
                        )

        return findings

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """Normalize alerts; flag unresolved malware and policy violations."""
        findings = []
        alerts = raw.raw_data.get("alerts", [])

        for alert in alerts:
            alert_id = alert.get("id", "")
            alert_type = alert.get("type", "")
            category = alert.get("category", "")
            severity_str = alert.get("severity", "medium").lower()
            description = alert.get("description", "")
            raised_at = alert.get("raisedAt", "")
            managed_agent = alert.get("managedAgent", {})
            agent_name = managed_agent.get("name", "") if isinstance(managed_agent, dict) else ""
            agent_id = managed_agent.get("id", "") if isinstance(managed_agent, dict) else ""
            product = alert.get("product", "")
            tenant_id = (
                alert.get("tenant", {}).get("id", "")
                if isinstance(alert.get("tenant"), dict)
                else ""
            )

            # Map Sophos severity
            severity = (
                severity_str
                if severity_str in ("critical", "high", "medium", "low", "info")
                else "medium"
            )

            # Determine observation type
            if category in ("malware", "ransomware"):
                obs_type = "alert"
            elif category in ("policy", "pua"):
                obs_type = "policy_violation"
            else:
                obs_type = "alert"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Sophos alert: {description or alert_type}",
                    detail={
                        "alert_id": alert_id,
                        "type": alert_type,
                        "category": category,
                        "description": description,
                        "severity": severity,
                        "raised_at": raised_at,
                        "agent_name": agent_name,
                        "agent_id": agent_id,
                        "product": product,
                        "tenant_id": tenant_id,
                    },
                    resource_id=alert_id,
                    resource_type="sophos_alert",
                    resource_name=description or alert_type,
                    account_id=tenant_id,
                    severity=severity,
                )
            )

            # Flag unresolved malware alerts specifically
            if category in ("malware", "ransomware"):
                alert_status = alert.get("status", "")
                if alert_status and alert_status.lower() not in ("resolved", "dismissed"):
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Unresolved malware: {description} on {agent_name}",
                            detail={
                                "alert_id": alert_id,
                                "category": category,
                                "description": description,
                                "status": alert_status,
                                "agent_name": agent_name,
                                "raised_at": raised_at,
                                "issue": f"Malware alert ({category}) is unresolved "
                                f"on endpoint {agent_name}",
                            },
                            resource_id=alert_id,
                            resource_type="sophos_alert",
                            resource_name=description or alert_type,
                            account_id=tenant_id,
                            severity="critical",
                        )
                    )

        return findings

    # -- Firewall Groups --

    def _normalize_firewall_groups(self, raw: RawEventData) -> list[FindingData]:
        """Inventory firewall groups and rules."""
        findings = []
        groups = raw.raw_data.get("groups", [])

        for group in groups:
            group_id = group.get("id", "")
            group_name = group.get("name", "")
            group_type = group.get("type", "")
            rules = group.get("rules", [])

            # Inventory the group
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Firewall group: {group_name} ({len(rules)} rules)",
                    detail={
                        "group_id": group_id,
                        "name": group_name,
                        "type": group_type,
                        "rule_count": len(rules),
                    },
                    resource_id=group_id,
                    resource_type="sophos_firewall_group",
                    resource_name=group_name,
                    severity="info",
                )
            )

            # Inventory each rule
            for rule in rules:
                rule_id = rule.get("id", "")
                rule_name = rule.get("name", "")
                action = rule.get("action", "")
                enabled = rule.get("enabled", True)
                direction = rule.get("direction", "")

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Firewall rule: {rule_name} ({action})",
                        detail={
                            "rule_id": rule_id,
                            "name": rule_name,
                            "group_id": group_id,
                            "group_name": group_name,
                            "action": action,
                            "enabled": enabled,
                            "direction": direction,
                        },
                        resource_id=rule_id,
                        resource_type="sophos_firewall_rule",
                        resource_name=rule_name,
                        severity="info",
                    )
                )

                # Flag disabled firewall rules
                if not enabled:
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="misconfiguration",
                            title=f"Firewall rule disabled: {rule_name} in {group_name}",
                            detail={
                                "rule_id": rule_id,
                                "name": rule_name,
                                "group_id": group_id,
                                "group_name": group_name,
                                "action": action,
                                "enabled": False,
                                "issue": "Firewall rule is disabled — traffic may bypass "
                                "intended security policy",
                            },
                            resource_id=rule_id,
                            resource_type="sophos_firewall_rule",
                            resource_name=rule_name,
                            severity="medium",
                        )
                    )

        return findings


# Register
registry.register(SophosNormalizer())
