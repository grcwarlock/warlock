"""Zscaler normalizer — transforms raw Zscaler ZIA API responses into Findings.

Handles web security policies, DLP policies, firewall rules, URL filtering rules,
and sandbox submissions.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ZscalerNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "zscaler_web_policies": "_normalize_web_policies",
        "zscaler_dlp_policies": "_normalize_dlp_policies",
        "zscaler_firewall_rules": "_normalize_firewall_rules",
        "zscaler_url_filter": "_normalize_url_filter",
        "zscaler_sandbox": "_normalize_sandbox",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "zscaler" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Zscaler findings."""
        return {
            "raw_event_id": raw.id,
            "source": "zscaler",
            "source_type": SourceType.NETWORK,
            "provider": "zscaler",
            "observed_at": raw.observed_at,
        }

    # -- Web Security Policies --

    def _normalize_web_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory web security policies; flag disabled ones."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", f"policy-{policy_id}")
            state = policy.get("state", policy.get("enabled", "ENABLED"))
            action = policy.get("action", "")
            protocols = policy.get("protocols", [])
            departments = policy.get("departments", [])
            groups = policy.get("groups", [])

            is_enabled = state in ("ENABLED", True, "enabled")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Web policy: {name} ({action})",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "state": state,
                        "action": action,
                        "protocols": protocols,
                        "departments": self._extract_names(departments),
                        "groups": self._extract_names(groups),
                    },
                    resource_id=policy_id,
                    resource_type="zscaler_web_policy",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag disabled policies
            if not is_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Web policy disabled: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "state": state,
                            "issue": "Web security policy is disabled and not enforcing protection",
                        },
                        resource_id=policy_id,
                        resource_type="zscaler_web_policy",
                        resource_name=name,
                        severity="medium",
                    )
                )

            # Flag permissive allow-all rules
            if action in ("ALLOW", "allow") and not departments and not groups:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Web policy allows all without scope: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "action": action,
                            "departments": [],
                            "groups": [],
                            "issue": "Allow policy has no department or group restrictions — applies globally",
                        },
                        resource_id=policy_id,
                        resource_type="zscaler_web_policy",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings

    # -- DLP Policies --

    def _normalize_dlp_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory DLP policies; flag disabled departments."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", f"dlp-{policy_id}")
            state = policy.get("state", policy.get("enabled", "ENABLED"))
            departments = policy.get("departments", [])
            excluded_departments = policy.get(
                "excludedDepartments", policy.get("excluded_departments", [])
            )

            is_enabled = state in ("ENABLED", True, "enabled")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"DLP policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "state": state,
                        "departments": self._extract_names(departments),
                        "excluded_departments": self._extract_names(excluded_departments),
                    },
                    resource_id=policy_id,
                    resource_type="zscaler_dlp_policy",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag disabled DLP policies
            if not is_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"DLP policy disabled: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "state": state,
                            "issue": "DLP policy is disabled — data loss prevention not enforced",
                        },
                        resource_id=policy_id,
                        resource_type="zscaler_dlp_policy",
                        resource_name=name,
                        severity="high",
                    )
                )

            # Flag departments excluded from DLP
            if excluded_departments:
                excl_names = self._extract_names(excluded_departments)
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"DLP exclusions for departments: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "excluded_departments": excl_names,
                            "issue": f"Departments excluded from DLP: {', '.join(excl_names)}",
                        },
                        resource_id=policy_id,
                        resource_type="zscaler_dlp_policy",
                        resource_name=name,
                        severity="medium",
                    )
                )

        return findings

    # -- Firewall Rules --

    def _normalize_firewall_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory cloud firewall rules; flag disabled and permissive rules."""
        findings = []
        rules = raw.raw_data.get("rules", [])

        for rule in rules:
            rule_id = str(rule.get("id", ""))
            name = rule.get("name", f"rule-{rule_id}")
            state = rule.get("state", rule.get("enabled", "ENABLED"))
            action = rule.get("action", "")
            src_ips = rule.get("srcIps", rule.get("src_ips", []))
            dest_addresses = rule.get("destAddresses", rule.get("dest_addresses", []))
            departments = rule.get("departments", [])

            is_enabled = state in ("ENABLED", True, "enabled")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Firewall rule: {name} ({action})",
                    detail={
                        "rule_id": rule_id,
                        "name": name,
                        "state": state,
                        "action": action,
                        "src_ips": src_ips,
                        "dest_addresses": dest_addresses,
                        "departments": self._extract_names(departments),
                    },
                    resource_id=rule_id,
                    resource_type="zscaler_firewall_rule",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag disabled rules
            if not is_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Firewall rule disabled: {name}",
                        detail={
                            "rule_id": rule_id,
                            "name": name,
                            "state": state,
                            "issue": "Cloud firewall rule is disabled",
                        },
                        resource_id=rule_id,
                        resource_type="zscaler_firewall_rule",
                        resource_name=name,
                        severity="medium",
                    )
                )

            # Flag allow-all rules
            is_allow = action in ("ALLOW", "allow")
            is_any_src = not src_ips or "Any" in src_ips or "*" in src_ips
            is_any_dst = not dest_addresses or "Any" in dest_addresses or "*" in dest_addresses

            if is_allow and is_any_src and is_any_dst:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Permissive firewall rule: {name} (any/any)",
                        detail={
                            "rule_id": rule_id,
                            "name": name,
                            "action": action,
                            "src_ips": src_ips,
                            "dest_addresses": dest_addresses,
                            "issue": "Firewall rule allows all traffic from any source to any destination",
                        },
                        resource_id=rule_id,
                        resource_type="zscaler_firewall_rule",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings

    # -- URL Filtering --

    def _normalize_url_filter(self, raw: RawEventData) -> list[FindingData]:
        """Inventory URL filtering rules; flag disabled rules."""
        findings = []
        rules = raw.raw_data.get("rules", [])

        for rule in rules:
            rule_id = str(rule.get("id", ""))
            name = rule.get("name", f"url-filter-{rule_id}")
            state = rule.get("state", rule.get("enabled", "ENABLED"))
            action = rule.get("action", "")
            url_categories = rule.get("urlCategories", rule.get("url_categories", []))
            departments = rule.get("departments", [])

            is_enabled = state in ("ENABLED", True, "enabled")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"URL filter rule: {name} ({action})",
                    detail={
                        "rule_id": rule_id,
                        "name": name,
                        "state": state,
                        "action": action,
                        "url_categories": url_categories,
                        "departments": self._extract_names(departments),
                    },
                    resource_id=rule_id,
                    resource_type="zscaler_url_filter_rule",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag disabled URL filter rules
            if not is_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"URL filter rule disabled: {name}",
                        detail={
                            "rule_id": rule_id,
                            "name": name,
                            "state": state,
                            "issue": "URL filtering rule is disabled — users may access blocked categories",
                        },
                        resource_id=rule_id,
                        resource_type="zscaler_url_filter_rule",
                        resource_name=name,
                        severity="medium",
                    )
                )

        return findings

    # -- Sandbox --

    def _normalize_sandbox(self, raw: RawEventData) -> list[FindingData]:
        """Flag sandbox malware detections."""
        findings = []
        submissions = raw.raw_data.get("submissions", [])

        for submission in submissions:
            sub_id = str(submission.get("id", submission.get("md5", "")))
            verdict = submission.get("verdict", submission.get("classification", "")).lower()
            filename = submission.get("fileName", submission.get("filename", ""))
            md5 = submission.get("md5", "")
            file_type = submission.get("fileType", submission.get("file_type", ""))
            submit_time = submission.get("submitTime", submission.get("submit_time", ""))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Sandbox submission: {filename} ({verdict})",
                    detail={
                        "submission_id": sub_id,
                        "filename": filename,
                        "md5": md5,
                        "verdict": verdict,
                        "file_type": file_type,
                        "submit_time": submit_time,
                    },
                    resource_id=sub_id,
                    resource_type="zscaler_sandbox_submission",
                    resource_name=filename,
                    severity="info",
                )
            )

            # Flag malware detections
            if verdict in ("malicious", "suspicious", "malware"):
                severity = "critical" if verdict == "malicious" or verdict == "malware" else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Sandbox malware detection: {filename}",
                        detail={
                            "submission_id": sub_id,
                            "filename": filename,
                            "md5": md5,
                            "verdict": verdict,
                            "file_type": file_type,
                            "submit_time": submit_time,
                            "issue": f"Sandbox classified file as {verdict}",
                        },
                        resource_id=sub_id,
                        resource_type="zscaler_sandbox_submission",
                        resource_name=filename,
                        severity=severity,
                    )
                )

        return findings

    # -- Helpers --

    @staticmethod
    def _extract_names(items: list) -> list[str]:
        """Extract names from Zscaler department/group objects."""
        if not items:
            return []
        names = []
        for item in items:
            if isinstance(item, dict):
                names.append(item.get("name", item.get("id", "")))
            else:
                names.append(str(item))
        return names


# Register
registry.register(ZscalerNormalizer())
