"""Auth0 normalizer — transforms raw Auth0 Management API responses into Findings.

Handles users, connections, rules/actions, and logs.
Flags: users without MFA enrolled, blocked users, deprecated legacy rules,
failed logins, anomalous login events.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Auth0 log event type codes for failed/anomalous events
# See: https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes
_FAILED_EVENT_TYPES = {
    "f",  # Failed login
    "fp",  # Failed login (incorrect password)
    "fu",  # Failed login (invalid email/username)
    "fco",  # Failed by connector
    "fcoa",  # Failed cross-origin authentication
    "fens",  # Failed exchange (native social login)
    "feacft",  # Failed exchange (authorization code for access token)
    "fepft",  # Failed exchange (password for access token)
    "fsa",  # Failed silent auth
    "fapi",  # Failed API operation
}

_ANOMALY_EVENT_TYPES = {
    "limit_mu",  # Blocked IP (too many login failures)
    "limit_wc",  # Blocked account
    "limit_ui",  # Too many signups from same IP
    "cls",  # Code/link sent (rate limit)
    "ublkdu",  # User block released
    "w",  # Warning
}


class Auth0Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "auth0_users": "_normalize_users",
        "auth0_connections": "_normalize_connections",
        "auth0_rules": "_normalize_rules",
        "auth0_logs": "_normalize_logs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "auth0" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Auth0 findings."""
        return {
            "raw_event_id": raw.id,
            "source": "auth0",
            "source_type": SourceType.IAM,
            "provider": "auth0",
            "observed_at": raw.observed_at,
        }

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag users without MFA and blocked users."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("user_id", "")
            email = user.get("email", "")
            name = user.get("name", user.get("nickname", ""))
            blocked = user.get("blocked", False)
            email_verified = user.get("email_verified", False)
            logins_count = user.get("logins_count", 0)
            last_login = user.get("last_login", "")
            created_at = user.get("created_at", "")
            # MFA enrollment — check multifactor array or guardian enrollments
            multifactor = user.get("multifactor", [])
            mfa_enrolled = (
                len(multifactor) > 0 if isinstance(multifactor, list) else bool(multifactor)
            )

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Auth0 user: {name or email}",
                    detail={
                        "user_id": user_id,
                        "email": email,
                        "name": name,
                        "blocked": blocked,
                        "email_verified": email_verified,
                        "mfa_enrolled": mfa_enrolled,
                        "logins_count": logins_count,
                        "last_login": last_login,
                        "created_at": created_at,
                    },
                    resource_id=user_id,
                    resource_type="auth0_user",
                    resource_name=name or email,
                    severity="info",
                )
            )

            # Flag users without MFA
            if not mfa_enrolled and not blocked:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"User without MFA enrolled: {name or email}",
                        detail={
                            "user_id": user_id,
                            "email": email,
                            "name": name,
                            "mfa_enrolled": False,
                            "issue": "Active user has no MFA factors enrolled — account relies on single-factor authentication",
                        },
                        resource_id=user_id,
                        resource_type="auth0_user",
                        resource_name=name or email,
                        severity="high",
                    )
                )

            # Flag blocked users
            if blocked:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Blocked user account: {name or email}",
                        detail={
                            "user_id": user_id,
                            "email": email,
                            "name": name,
                            "blocked": True,
                            "issue": "User account is blocked — review for suspicious activity or deprovisioning",
                        },
                        resource_id=user_id,
                        resource_type="auth0_user",
                        resource_name=name or email,
                        severity="medium",
                    )
                )

            # Flag unverified email
            if not email_verified and not blocked:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unverified email: {name or email}",
                        detail={
                            "user_id": user_id,
                            "email": email,
                            "name": name,
                            "email_verified": False,
                            "issue": "User email is not verified — identity cannot be confirmed",
                        },
                        resource_id=user_id,
                        resource_type="auth0_user",
                        resource_name=name or email,
                        severity="medium",
                    )
                )

        return findings

    # -- Connections --

    def _normalize_connections(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Auth0 connections (identity providers)."""
        findings = []
        connections = raw.raw_data.get("connections", [])

        for conn in connections:
            conn_id = conn.get("id", "")
            conn_name = conn.get("name", "")
            strategy = conn.get("strategy", "")
            enabled_clients = conn.get("enabled_clients", [])
            is_domain_connection = conn.get("is_domain_connection", False)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Auth0 connection: {conn_name} ({strategy})",
                    detail={
                        "connection_id": conn_id,
                        "connection_name": conn_name,
                        "strategy": strategy,
                        "enabled_clients_count": len(enabled_clients),
                        "is_domain_connection": is_domain_connection,
                    },
                    resource_id=conn_id,
                    resource_type="auth0_connection",
                    resource_name=conn_name,
                    severity="info",
                )
            )

        return findings

    # -- Rules / Actions --

    def _normalize_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory rules and actions; flag deprecated legacy rules."""
        findings = []

        # Legacy rules
        rules = raw.raw_data.get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "")
            rule_name = rule.get("name", "")
            enabled = rule.get("enabled", True)
            stage = rule.get("stage", "")
            order = rule.get("order", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Auth0 rule (legacy): {rule_name}",
                    detail={
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "enabled": enabled,
                        "stage": stage,
                        "order": order,
                        "type": "legacy_rule",
                    },
                    resource_id=rule_id,
                    resource_type="auth0_rule",
                    resource_name=rule_name,
                    severity="info",
                )
            )

            # Flag legacy rules — Auth0 deprecated rules in favor of actions
            if enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Deprecated legacy rule active: {rule_name}",
                        detail={
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "enabled": True,
                            "issue": "Auth0 Rules are deprecated — migrate to Actions for continued support and security updates",
                        },
                        resource_id=rule_id,
                        resource_type="auth0_rule",
                        resource_name=rule_name,
                        severity="medium",
                    )
                )

        # Actions
        actions = raw.raw_data.get("actions", [])
        for action in actions:
            action_id = action.get("id", "")
            action_name = action.get("name", "")
            status = action.get("status", "")
            supported_triggers = action.get("supported_triggers", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Auth0 action: {action_name} ({status})",
                    detail={
                        "action_id": action_id,
                        "action_name": action_name,
                        "status": status,
                        "supported_triggers": supported_triggers,
                        "type": "action",
                    },
                    resource_id=action_id,
                    resource_type="auth0_action",
                    resource_name=action_name,
                    severity="info",
                )
            )

        return findings

    # -- Logs --

    def _normalize_logs(self, raw: RawEventData) -> list[FindingData]:
        """Alert on failed and anomalous login events."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        for entry in logs:
            log_id = entry.get("_id", entry.get("log_id", ""))
            event_type = entry.get("type", "")
            description = entry.get("description", "")
            date = entry.get("date", "")
            client_name = entry.get("client_name", "")
            ip = entry.get("ip", "")
            user_agent = entry.get("user_agent", "")
            user_id = entry.get("user_id", "")
            user_name = entry.get("user_name", entry.get("details", {}).get("email", ""))
            connection = entry.get("connection", "")
            location = entry.get("location_info", {})

            # Flag failed login events
            if event_type in _FAILED_EVENT_TYPES:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Failed login: {user_name or user_id} ({event_type})",
                        detail={
                            "log_id": log_id,
                            "event_type": event_type,
                            "description": description,
                            "user_id": user_id,
                            "user_name": user_name,
                            "client_name": client_name,
                            "ip": ip,
                            "user_agent": user_agent,
                            "connection": connection,
                            "date": date,
                            "location": location,
                            "issue": f"Authentication failed: {description or event_type}",
                        },
                        resource_id=log_id,
                        resource_type="auth0_log_event",
                        resource_name=f"failed:{user_name or user_id}",
                        severity="medium",
                    )
                )

            # Flag anomaly / rate-limit events
            elif event_type in _ANOMALY_EVENT_TYPES:
                severity = "critical" if event_type.startswith("limit_") else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Login anomaly detected: {description or event_type}",
                        detail={
                            "log_id": log_id,
                            "event_type": event_type,
                            "description": description,
                            "user_id": user_id,
                            "user_name": user_name,
                            "ip": ip,
                            "date": date,
                            "location": location,
                            "issue": f"Anomalous authentication activity: {description or event_type} — possible brute-force or credential stuffing",
                        },
                        resource_id=log_id,
                        resource_type="auth0_log_event",
                        resource_name=f"anomaly:{user_name or ip}",
                        severity=severity,
                    )
                )

        return findings


# Register
registry.register(Auth0Normalizer())
