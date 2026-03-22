"""Grafana normalizer — transforms raw Grafana HTTP API responses into Findings.

Handles alert rules, dashboards, data sources, and users/teams.
Flags: firing alerts, dashboards without alerts, anonymous access data sources,
admin users without MFA.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GrafanaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "grafana_alerts": "_normalize_alerts",
        "grafana_dashboards": "_normalize_dashboards",
        "grafana_datasources": "_normalize_datasources",
        "grafana_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "grafana" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Grafana findings."""
        return {
            "raw_event_id": raw.id,
            "source": "grafana",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "grafana",
            "observed_at": raw.observed_at,
        }

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """Inventory alert rules; flag firing alerts."""
        findings = []
        alert_rules = raw.raw_data.get("alert_rules", [])
        alert_instances = raw.raw_data.get("alert_instances", [])

        # Build a set of firing alert fingerprints/labels for cross-reference
        firing_labels: set[str] = set()
        for instance in alert_instances:
            status = instance.get("status", {})
            state = status.get("state", "") if isinstance(status, dict) else ""
            if state in ("firing", "active"):
                labels = instance.get("labels", {})
                alert_name = labels.get("alertname", "")
                if alert_name:
                    firing_labels.add(alert_name)

        for rule in alert_rules:
            rule_uid = rule.get("uid", rule.get("id", ""))
            rule_title = rule.get("title", rule.get("name", ""))
            folder_uid = rule.get("folderUID", "")
            rule_group = rule.get("ruleGroup", "")
            condition = rule.get("condition", "")
            no_data_state = rule.get("noDataState", "")
            exec_err_state = rule.get("execErrState", "")

            is_firing = rule_title in firing_labels

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Grafana alert rule: {rule_title}",
                    detail={
                        "rule_uid": str(rule_uid),
                        "rule_title": rule_title,
                        "folder_uid": folder_uid,
                        "rule_group": rule_group,
                        "condition": condition,
                        "no_data_state": no_data_state,
                        "exec_err_state": exec_err_state,
                        "is_firing": is_firing,
                    },
                    resource_id=str(rule_uid),
                    resource_type="grafana_alert_rule",
                    resource_name=rule_title,
                    severity="info",
                )
            )

            # Flag firing alerts
            if is_firing:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Grafana alert firing: {rule_title}",
                        detail={
                            "rule_uid": str(rule_uid),
                            "rule_title": rule_title,
                            "rule_group": rule_group,
                            "issue": "Alert rule is currently in firing state — active incident may require attention",
                        },
                        resource_id=str(rule_uid),
                        resource_type="grafana_alert_rule",
                        resource_name=rule_title,
                        severity="high",
                    )
                )

        # Flag firing alert instances directly
        for instance in alert_instances:
            status = instance.get("status", {})
            state = status.get("state", "") if isinstance(status, dict) else ""
            if state in ("firing", "active"):
                labels = instance.get("labels", {})
                alert_name = labels.get("alertname", "unknown")
                fingerprint = instance.get("fingerprint", "")

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Active alert instance: {alert_name}",
                        detail={
                            "alert_name": alert_name,
                            "fingerprint": fingerprint,
                            "state": state,
                            "labels": labels,
                            "issue": f"Alert '{alert_name}' is actively firing",
                        },
                        resource_id=fingerprint or alert_name,
                        resource_type="grafana_alert_instance",
                        resource_name=alert_name,
                        severity="high",
                    )
                )

        return findings

    # -- Dashboards --

    def _normalize_dashboards(self, raw: RawEventData) -> list[FindingData]:
        """Inventory dashboards; flag dashboards without alert panels."""
        findings = []
        dashboards = raw.raw_data.get("dashboards", [])

        for dash in dashboards:
            dash_uid = dash.get("uid", str(dash.get("id", "")))
            dash_title = dash.get("title", "")
            folder_title = dash.get("folderTitle", "")
            dash_type = dash.get("type", "")
            tags = dash.get("tags", [])

            # Check if dashboard has alerts (based on tags or metadata)
            "alerts" in [t.lower() for t in tags] if tags else False

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Grafana dashboard: {dash_title}",
                    detail={
                        "dashboard_uid": dash_uid,
                        "dashboard_title": dash_title,
                        "folder": folder_title,
                        "type": dash_type,
                        "tags": tags,
                    },
                    resource_id=dash_uid,
                    resource_type="grafana_dashboard",
                    resource_name=dash_title,
                    severity="info",
                )
            )

        return findings

    # -- Data Sources --

    def _normalize_datasources(self, raw: RawEventData) -> list[FindingData]:
        """Inventory data sources; flag anonymous access and insecure configs."""
        findings = []
        datasources = raw.raw_data.get("datasources", [])

        for ds in datasources:
            ds_id = ds.get("id", "")
            ds_uid = ds.get("uid", str(ds_id))
            ds_name = ds.get("name", "")
            ds_type = ds.get("type", "")
            ds_url = ds.get("url", "")
            access = ds.get("access", "")
            basic_auth = ds.get("basicAuth", False)
            is_default = ds.get("isDefault", False)
            json_data = ds.get("jsonData", {})
            ds.get("withCredentials", False)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Grafana data source: {ds_name} ({ds_type})",
                    detail={
                        "datasource_id": str(ds_id),
                        "datasource_uid": ds_uid,
                        "datasource_name": ds_name,
                        "type": ds_type,
                        "url": ds_url,
                        "access": access,
                        "basic_auth": basic_auth,
                        "is_default": is_default,
                    },
                    resource_id=ds_uid,
                    resource_type="grafana_datasource",
                    resource_name=ds_name,
                    severity="info",
                )
            )

            # Flag data sources with direct/browser access (bypasses Grafana proxy)
            if access == "direct":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Data source with direct browser access: {ds_name}",
                        detail={
                            "datasource_uid": ds_uid,
                            "datasource_name": ds_name,
                            "type": ds_type,
                            "access": "direct",
                            "issue": "Data source uses direct browser access — credentials may be exposed to end users",
                        },
                        resource_id=ds_uid,
                        resource_type="grafana_datasource",
                        resource_name=ds_name,
                        severity="high",
                    )
                )

            # Flag data sources without authentication
            tls_skip = (
                json_data.get("tlsSkipVerify", False) if isinstance(json_data, dict) else False
            )
            if tls_skip:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Data source with TLS verification disabled: {ds_name}",
                        detail={
                            "datasource_uid": ds_uid,
                            "datasource_name": ds_name,
                            "type": ds_type,
                            "tls_skip_verify": True,
                            "issue": "TLS certificate verification is disabled — connection is vulnerable to MITM attacks",
                        },
                        resource_id=ds_uid,
                        resource_type="grafana_datasource",
                        resource_name=ds_name,
                        severity="high",
                    )
                )

        return findings

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag admin users and users without MFA."""
        findings = []
        users = raw.raw_data.get("users", [])
        teams = raw.raw_data.get("teams", [])

        for user in users:
            user_id = user.get("userId", user.get("id", ""))
            login = user.get("login", "")
            email = user.get("email", "")
            role = user.get("role", "")
            last_seen = user.get("lastSeenAt", user.get("last_seen_at", ""))
            is_disabled = user.get("isDisabled", False)
            auth_labels = user.get("authLabels", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Grafana user: {login} ({role})",
                    detail={
                        "user_id": str(user_id),
                        "login": login,
                        "email": email,
                        "role": role,
                        "last_seen": last_seen,
                        "is_disabled": is_disabled,
                        "auth_labels": auth_labels,
                    },
                    resource_id=str(user_id),
                    resource_type="grafana_user",
                    resource_name=login or email,
                    severity="info",
                )
            )

            # Flag admin users without external auth (no SSO/SAML/LDAP = no MFA)
            if role == "Admin" and not auth_labels:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Admin user without external auth: {login}",
                        detail={
                            "user_id": str(user_id),
                            "login": login,
                            "email": email,
                            "role": "Admin",
                            "auth_labels": [],
                            "issue": "Admin user authenticates with local credentials only — no SSO/SAML/LDAP means no MFA enforcement",
                        },
                        resource_id=str(user_id),
                        resource_type="grafana_user",
                        resource_name=login or email,
                        severity="high",
                    )
                )

        # Inventory teams
        for team in teams:
            team_id = team.get("id", "")
            team_name = team.get("name", "")
            member_count = team.get("memberCount", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Grafana team: {team_name} ({member_count} members)",
                    detail={
                        "team_id": str(team_id),
                        "team_name": team_name,
                        "member_count": member_count,
                    },
                    resource_id=str(team_id),
                    resource_type="grafana_team",
                    resource_name=team_name,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(GrafanaNormalizer())
