"""Cloudflare normalizer — transforms raw Cloudflare API responses into Findings.

Handles WAF rules, DNS records, Zero Trust Access apps, Gateway rules,
SSL/TLS settings, Page Shield scripts, and audit logs.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Audit log actions considered sensitive
SENSITIVE_AUDIT_ACTIONS = {
    "account_settings_changed",
    "api_key_created",
    "api_key_deleted",
    "member_added",
    "member_removed",
    "member_role_changed",
    "zone_created",
    "zone_deleted",
    "access_policy_created",
    "access_policy_deleted",
    "dns_record_created",
    "dns_record_deleted",
    "firewall_rule_created",
    "firewall_rule_deleted",
    "waf_rule_group_changed",
    "ssl_setting_changed",
    "token_created",
    "token_deleted",
}


class CloudflareNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "cf_waf_rules": "_normalize_waf_rules",
        "cf_dns_records": "_normalize_dns_records",
        "cf_access_apps": "_normalize_access_apps",
        "cf_gateway_rules": "_normalize_gateway_rules",
        "cf_ssl_settings": "_normalize_ssl_settings",
        "cf_page_shield": "_normalize_page_shield",
        "cf_audit_logs": "_normalize_audit_logs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cloudflare" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Cloudflare findings."""
        return {
            "raw_event_id": raw.id,
            "source": "cloudflare",
            "source_type": SourceType.CLOUD,
            "provider": "cloudflare",
            "observed_at": raw.observed_at,
        }

    # -- WAF Rules --

    def _normalize_waf_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory WAF rules; flag disabled or overly permissive ones."""
        findings = []
        zone_id = raw.raw_data.get("zone_id", "")
        rules = raw.raw_data.get("rules", [])

        for rule in rules:
            rule_id = rule.get("id", "")
            mode = rule.get("mode", "")
            config = rule.get("configuration", {})
            target = config.get("target", "")
            value = config.get("value", "")
            notes = rule.get("notes", "")

            # Inventory for every rule
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"WAF rule: {mode} {target} {value}",
                detail={
                    "rule_id": rule_id,
                    "mode": mode,
                    "target": target,
                    "value": value,
                    "notes": notes,
                    "zone_id": zone_id,
                },
                resource_id=rule_id,
                resource_type="cloudflare_waf_rule",
                resource_name=f"{target}:{value}",
                account_id=zone_id,
                severity="info",
            ))

            # Flag disabled rules
            if mode in ("disabled", ""):
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"WAF rule disabled: {target} {value}",
                    detail={
                        "rule_id": rule_id,
                        "mode": mode,
                        "target": target,
                        "value": value,
                        "issue": "WAF rule is disabled and not enforcing protection",
                        "zone_id": zone_id,
                    },
                    resource_id=rule_id,
                    resource_type="cloudflare_waf_rule",
                    resource_name=f"{target}:{value}",
                    account_id=zone_id,
                    severity="medium",
                ))

            # Flag permissive modes (whitelist/js_challenge when block expected)
            if mode in ("whitelist",):
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"WAF rule is permissive (whitelist): {target} {value}",
                    detail={
                        "rule_id": rule_id,
                        "mode": mode,
                        "target": target,
                        "value": value,
                        "issue": "WAF rule uses whitelist mode, bypassing protection",
                        "zone_id": zone_id,
                    },
                    resource_id=rule_id,
                    resource_type="cloudflare_waf_rule",
                    resource_name=f"{target}:{value}",
                    account_id=zone_id,
                    severity="medium",
                ))

        return findings

    # -- DNS Records --

    def _normalize_dns_records(self, raw: RawEventData) -> list[FindingData]:
        """Inventory DNS records; flag CNAME to uncontrolled origins, unproxied records."""
        findings = []
        zone_id = raw.raw_data.get("zone_id", "")
        records = raw.raw_data.get("records", [])

        for rec in records:
            rec_id = rec.get("id", "")
            rec_type = rec.get("type", "")
            name = rec.get("name", "")
            content = rec.get("content", "")
            proxied = rec.get("proxied", False)
            ttl = rec.get("ttl", 0)

            # Inventory
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"DNS {rec_type}: {name} -> {content}",
                detail={
                    "record_id": rec_id,
                    "type": rec_type,
                    "name": name,
                    "content": content,
                    "proxied": proxied,
                    "ttl": ttl,
                    "zone_id": zone_id,
                },
                resource_id=rec_id,
                resource_type="cloudflare_dns_record",
                resource_name=name,
                account_id=zone_id,
                severity="info",
            ))

            # Flag CNAME pointing to external / uncontrolled origins
            if rec_type == "CNAME" and not content.endswith(".cdn.cloudflare.net"):
                # External CNAME that could be a dangling pointer or subdomain takeover risk
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"CNAME to external origin: {name} -> {content}",
                    detail={
                        "record_id": rec_id,
                        "name": name,
                        "content": content,
                        "proxied": proxied,
                        "issue": "CNAME points to an external origin — verify ownership to prevent subdomain takeover",
                        "zone_id": zone_id,
                    },
                    resource_id=rec_id,
                    resource_type="cloudflare_dns_record",
                    resource_name=name,
                    account_id=zone_id,
                    severity="low",
                ))

            # Flag A/AAAA/CNAME records not proxied through Cloudflare
            if rec_type in ("A", "AAAA", "CNAME") and not proxied:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"DNS record not proxied: {name} ({rec_type})",
                    detail={
                        "record_id": rec_id,
                        "type": rec_type,
                        "name": name,
                        "content": content,
                        "proxied": proxied,
                        "issue": "Record bypasses Cloudflare proxy — origin IP exposed, no WAF/DDoS protection",
                        "zone_id": zone_id,
                    },
                    resource_id=rec_id,
                    resource_type="cloudflare_dns_record",
                    resource_name=name,
                    account_id=zone_id,
                    severity="low",
                ))

        return findings

    # -- Zero Trust Access Apps --

    def _normalize_access_apps(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Access applications; check session duration and purpose justification."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        apps = raw.raw_data.get("apps", [])

        for app in apps:
            app_id = app.get("id", "")
            app_name = app.get("name", "")
            app_type = app.get("type", "")
            domain = app.get("domain", "")
            session_duration = app.get("session_duration", "")
            purpose_justification = app.get("purpose_justification_required", False)
            allowed_idps = app.get("allowed_idps", [])

            # Inventory
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Access app: {app_name} ({app_type})",
                detail={
                    "app_id": app_id,
                    "name": app_name,
                    "type": app_type,
                    "domain": domain,
                    "session_duration": session_duration,
                    "purpose_justification_required": purpose_justification,
                    "allowed_idps": allowed_idps,
                    "account_id": account_id,
                },
                resource_id=app_id,
                resource_type="cloudflare_access_app",
                resource_name=app_name,
                account_id=account_id,
                severity="info",
            ))

            # Flag long session durations (> 24h)
            if session_duration and self._session_hours(session_duration) > 24:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Access app excessive session duration: {app_name} ({session_duration})",
                    detail={
                        "app_id": app_id,
                        "name": app_name,
                        "session_duration": session_duration,
                        "issue": "Session duration exceeds 24 hours — increases risk if credentials are compromised",
                        "account_id": account_id,
                    },
                    resource_id=app_id,
                    resource_type="cloudflare_access_app",
                    resource_name=app_name,
                    account_id=account_id,
                    severity="medium",
                ))

            # Flag missing purpose justification
            if not purpose_justification:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Access app missing purpose justification: {app_name}",
                    detail={
                        "app_id": app_id,
                        "name": app_name,
                        "purpose_justification_required": False,
                        "issue": "Purpose justification not required — reduces audit trail for access decisions",
                        "account_id": account_id,
                    },
                    resource_id=app_id,
                    resource_type="cloudflare_access_app",
                    resource_name=app_name,
                    account_id=account_id,
                    severity="low",
                ))

        return findings

    @staticmethod
    def _session_hours(duration_str: str) -> float:
        """Parse Cloudflare session duration string (e.g. '24h', '720h', '30m') to hours."""
        try:
            duration_str = duration_str.strip().lower()
            if duration_str.endswith("h"):
                return float(duration_str[:-1])
            if duration_str.endswith("m"):
                return float(duration_str[:-1]) / 60
            if duration_str.endswith("d"):
                return float(duration_str[:-1]) * 24
            return float(duration_str)
        except (ValueError, TypeError):
            return 0.0

    # -- Zero Trust Gateway Rules --

    def _normalize_gateway_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Gateway rules; check enabled ratio and coverage."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        rules = raw.raw_data.get("rules", [])

        total = len(rules)
        enabled_count = sum(1 for r in rules if r.get("enabled", False))

        for rule in rules:
            rule_id = rule.get("id", "")
            rule_name = rule.get("name", "")
            enabled = rule.get("enabled", False)
            action = rule.get("action", "")
            traffic = rule.get("traffic", "")
            filters = rule.get("filters", [])

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Gateway rule: {rule_name} ({action})",
                detail={
                    "rule_id": rule_id,
                    "name": rule_name,
                    "enabled": enabled,
                    "action": action,
                    "traffic": traffic,
                    "filters": filters,
                    "account_id": account_id,
                },
                resource_id=rule_id,
                resource_type="cloudflare_gateway_rule",
                resource_name=rule_name,
                account_id=account_id,
                severity="info",
            ))

        # Flag low rule coverage
        if total > 0 and enabled_count < total:
            disabled_count = total - enabled_count
            coverage_pct = round(enabled_count / total * 100, 1)
            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration",
                title=f"Gateway rules: {disabled_count}/{total} disabled ({coverage_pct}% coverage)",
                detail={
                    "total_rules": total,
                    "enabled_rules": enabled_count,
                    "disabled_rules": disabled_count,
                    "coverage_percent": coverage_pct,
                    "issue": "Not all Gateway rules are enabled — disabled rules reduce threat coverage",
                    "account_id": account_id,
                },
                resource_id=account_id,
                resource_type="cloudflare_gateway",
                resource_name="gateway_rules",
                account_id=account_id,
                severity="medium" if coverage_pct < 50 else "low",
            ))

        return findings

    # -- SSL/TLS Settings --

    def _normalize_ssl_settings(self, raw: RawEventData) -> list[FindingData]:
        """Check SSL mode, minimum TLS version, and HTTPS enforcement."""
        findings = []
        zone_id = raw.raw_data.get("zone_id", "")
        ssl = raw.raw_data.get("ssl", {})
        min_tls = raw.raw_data.get("min_tls_version", {})
        always_https = raw.raw_data.get("always_use_https", {})

        ssl_mode = ssl.get("value", "") if isinstance(ssl, dict) else str(ssl)
        tls_version = min_tls.get("value", "") if isinstance(min_tls, dict) else str(min_tls)
        https_enforced = always_https.get("value", "off") if isinstance(always_https, dict) else str(always_https)

        # Inventory
        findings.append(FindingData(
            **self._base(raw),
            observation_type="inventory",
            title=f"SSL/TLS settings: mode={ssl_mode}, min_tls={tls_version}, https={https_enforced}",
            detail={
                "ssl_mode": ssl_mode,
                "min_tls_version": tls_version,
                "always_use_https": https_enforced,
                "zone_id": zone_id,
            },
            resource_id=zone_id,
            resource_type="cloudflare_zone_ssl",
            resource_name=f"zone:{zone_id}",
            account_id=zone_id,
            severity="info",
        ))

        # Flag SSL mode not full_strict
        if ssl_mode and ssl_mode not in ("full", "strict", "full_strict"):
            severity = "high" if ssl_mode in ("off", "flexible") else "medium"
            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration",
                title=f"SSL mode not strict: {ssl_mode}",
                detail={
                    "ssl_mode": ssl_mode,
                    "expected": "full_strict",
                    "issue": f"SSL mode '{ssl_mode}' does not validate origin certificates — vulnerable to MITM",
                    "zone_id": zone_id,
                },
                resource_id=zone_id,
                resource_type="cloudflare_zone_ssl",
                resource_name=f"zone:{zone_id}",
                account_id=zone_id,
                severity=severity,
            ))

        # Flag TLS version < 1.2
        if tls_version and tls_version in ("1.0", "1.1"):
            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration",
                title=f"Minimum TLS version too low: {tls_version}",
                detail={
                    "min_tls_version": tls_version,
                    "expected": "1.2 or higher",
                    "issue": f"TLS {tls_version} has known vulnerabilities and is deprecated",
                    "zone_id": zone_id,
                },
                resource_id=zone_id,
                resource_type="cloudflare_zone_ssl",
                resource_name=f"zone:{zone_id}",
                account_id=zone_id,
                severity="high",
            ))

        # Flag HTTPS not enforced
        if https_enforced != "on":
            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration",
                title="Always Use HTTPS not enabled",
                detail={
                    "always_use_https": https_enforced,
                    "issue": "HTTP traffic is not automatically redirected to HTTPS",
                    "zone_id": zone_id,
                },
                resource_id=zone_id,
                resource_type="cloudflare_zone_ssl",
                resource_name=f"zone:{zone_id}",
                account_id=zone_id,
                severity="medium",
            ))

        return findings

    # -- Page Shield --

    def _normalize_page_shield(self, raw: RawEventData) -> list[FindingData]:
        """Inventory scripts; alert on malicious detections."""
        findings = []
        zone_id = raw.raw_data.get("zone_id", "")
        scripts = raw.raw_data.get("scripts", [])

        for script in scripts:
            script_id = script.get("id", "")
            script_url = script.get("url", "")
            host = script.get("host", "")
            malicious = script.get("malicious", False)
            js_integrity_score = script.get("js_integrity_score", None)
            fetched_at = script.get("fetched_at", "")
            first_seen = script.get("first_seen_at", "")
            last_seen = script.get("last_seen_at", "")

            # Inventory
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Page Shield script: {script_url}",
                detail={
                    "script_id": script_id,
                    "url": script_url,
                    "host": host,
                    "malicious": malicious,
                    "js_integrity_score": js_integrity_score,
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "fetched_at": fetched_at,
                    "zone_id": zone_id,
                },
                resource_id=script_id,
                resource_type="cloudflare_page_shield_script",
                resource_name=script_url,
                account_id=zone_id,
                severity="info",
            ))

            # Alert on malicious scripts
            if malicious:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Malicious script detected: {script_url}",
                    detail={
                        "script_id": script_id,
                        "url": script_url,
                        "host": host,
                        "malicious": True,
                        "js_integrity_score": js_integrity_score,
                        "first_seen_at": first_seen,
                        "last_seen_at": last_seen,
                        "issue": "Page Shield flagged this script as malicious — possible supply chain attack",
                        "zone_id": zone_id,
                    },
                    resource_id=script_id,
                    resource_type="cloudflare_page_shield_script",
                    resource_name=script_url,
                    account_id=zone_id,
                    severity="critical",
                ))

        return findings

    # -- Audit Logs --

    def _normalize_audit_logs(self, raw: RawEventData) -> list[FindingData]:
        """Alert on sensitive audit actions."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        logs = raw.raw_data.get("logs", [])

        for entry in logs:
            entry_id = entry.get("id", "")
            action = entry.get("action", {})
            action_type = action.get("type", "") if isinstance(action, dict) else str(action)
            actor = entry.get("actor", {})
            actor_email = actor.get("email", "") if isinstance(actor, dict) else ""
            actor_type = actor.get("type", "") if isinstance(actor, dict) else ""
            when = entry.get("when", "")
            resource = entry.get("resource", {})
            resource_type = resource.get("type", "") if isinstance(resource, dict) else ""
            resource_id_val = resource.get("id", "") if isinstance(resource, dict) else ""
            metadata = entry.get("metadata", {})

            # Only alert on sensitive actions
            if action_type in SENSITIVE_AUDIT_ACTIONS:
                severity = "high" if action_type in (
                    "api_key_created", "api_key_deleted",
                    "member_added", "member_removed", "member_role_changed",
                    "token_created", "token_deleted",
                    "account_settings_changed",
                ) else "medium"

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Audit: {action_type} by {actor_email or actor_type}",
                    detail={
                        "log_id": entry_id,
                        "action_type": action_type,
                        "actor_email": actor_email,
                        "actor_type": actor_type,
                        "when": when,
                        "resource_type": resource_type,
                        "resource_id": resource_id_val,
                        "metadata": metadata,
                        "account_id": account_id,
                    },
                    resource_id=resource_id_val or entry_id,
                    resource_type=resource_type or "cloudflare_audit_log",
                    resource_name=f"{action_type}",
                    account_id=account_id,
                    severity=severity,
                ))

        return findings


# Register
registry.register(CloudflareNormalizer())
