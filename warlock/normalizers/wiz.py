"""Wiz normalizer — transforms raw Wiz GraphQL responses into Findings.

Handles issues, configuration findings, and vulnerability findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WizNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "wiz_issues": "_normalize_issues",
        "wiz_config_findings": "_normalize_config_findings",
        "wiz_vuln_findings": "_normalize_vuln_findings",
        "wiz_graph": "_normalize_graph",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "wiz" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Wiz findings."""
        return {
            "raw_event_id": raw.id,
            "source": "wiz",
            "source_type": SourceType.SCANNER,
            "provider": "wiz",
            "observed_at": raw.observed_at,
        }

    @staticmethod
    def _wiz_severity(sev: str) -> str:
        """Map Wiz severity to standard severity."""
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "info",
            "NONE": "info",
        }
        return mapping.get(sev.upper(), "medium") if sev else "medium"

    # -- Issues --

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        """One finding per Wiz issue."""
        findings = []
        issues = raw.raw_data.get("issues", [])

        for issue in issues:
            severity = self._wiz_severity(issue.get("severity", ""))
            entity = issue.get("entity", {}) or {}
            source_rule = issue.get("sourceRule", {}) or {}
            projects = issue.get("projects", []) or []
            project_names = [p.get("name", "") for p in projects if p]

            obs_type = "alert"
            issue_type = issue.get("type", "").upper()
            if issue_type in ("TOXIC_COMBINATION", "THREAT_DETECTION"):
                obs_type = "alert"
            elif issue_type in ("CONFIGURATION", "CLOUD_CONFIGURATION"):
                obs_type = "misconfiguration"
            elif issue_type == "VULNERABILITY":
                obs_type = "vulnerability"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=issue.get("title", "Wiz Issue"),
                detail={
                    "issue_id": issue.get("id", ""),
                    "type": issue.get("type", ""),
                    "status": issue.get("status", ""),
                    "entity_id": entity.get("id", ""),
                    "entity_type": entity.get("type", ""),
                    "entity_name": entity.get("name", ""),
                    "rule_id": source_rule.get("id", ""),
                    "rule_name": source_rule.get("name", ""),
                    "projects": project_names,
                    "created_at": issue.get("createdAt", ""),
                    "due_at": issue.get("dueAt", ""),
                },
                resource_id=entity.get("id", ""),
                resource_type=entity.get("type", ""),
                resource_name=entity.get("name", ""),
                severity=severity,
            ))

        return findings

    # -- Configuration Findings --

    def _normalize_config_findings(self, raw: RawEventData) -> list[FindingData]:
        """One finding per cloud configuration finding."""
        findings = []
        config_findings = raw.raw_data.get("findings", [])

        for cf in config_findings:
            severity = self._wiz_severity(cf.get("severity", ""))
            resource = cf.get("resource", {}) or {}
            rule = cf.get("rule", {}) or {}
            subscription = resource.get("subscription", {}) or {}

            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration",
                title=cf.get("title", "") or rule.get("name", "Configuration finding"),
                detail={
                    "finding_id": cf.get("id", ""),
                    "result": cf.get("result", ""),
                    "status": cf.get("status", ""),
                    "rule_id": rule.get("id", ""),
                    "rule_name": rule.get("name", ""),
                    "rule_description": rule.get("description", ""),
                    "remediation": rule.get("remediationInstructions", ""),
                    "resource_native_type": resource.get("nativeType", ""),
                    "subscription_id": subscription.get("id", ""),
                    "subscription_name": subscription.get("name", ""),
                    "analyzed_at": cf.get("analyzedAt", ""),
                },
                resource_id=resource.get("id", ""),
                resource_type=resource.get("type", ""),
                resource_name=resource.get("name", ""),
                region=resource.get("region", ""),
                account_id=subscription.get("id", ""),
                severity=severity,
            ))

        return findings

    # -- Vulnerability Findings --

    def _normalize_vuln_findings(self, raw: RawEventData) -> list[FindingData]:
        """One finding per vulnerability finding."""
        findings = []
        vuln_findings = raw.raw_data.get("findings", [])

        for vf in vuln_findings:
            severity = self._wiz_severity(vf.get("severity", ""))
            asset = vf.get("vulnerableAsset", {}) or {}
            subscription = asset.get("subscription", {}) or {}

            cve_desc = vf.get("CVEDescription", "")
            cvss = vf.get("CVSSScore", 0)
            name = vf.get("name", "") or vf.get("detailedName", "Vulnerability")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="vulnerability",
                title=f"{name}" + (f" (CVSS {cvss})" if cvss else ""),
                detail={
                    "finding_id": vf.get("id", ""),
                    "name": name,
                    "detailed_name": vf.get("detailedName", ""),
                    "cve_description": cve_desc,
                    "cvss_score": cvss,
                    "has_exploit": vf.get("hasExploit", False),
                    "has_cisa_kev": vf.get("hasCISAKEVExploit", False),
                    "version": vf.get("version", ""),
                    "fixed_version": vf.get("fixedVersion", ""),
                    "vendor_severity": vf.get("vendorSeverity", ""),
                    "status": vf.get("status", ""),
                    "first_detected": vf.get("firstDetectedAt", ""),
                    "last_detected": vf.get("lastDetectedAt", ""),
                    "subscription_id": subscription.get("id", ""),
                    "subscription_name": subscription.get("name", ""),
                },
                resource_id=asset.get("id", ""),
                resource_type=asset.get("type", ""),
                resource_name=asset.get("name", ""),
                region=asset.get("region", ""),
                account_id=subscription.get("id", ""),
                severity=severity,
            ))

        return findings

    # -- Graph --

    def _normalize_graph(self, raw: RawEventData) -> list[FindingData]:
        """Security graph entities as inventory."""
        findings = []
        graph_nodes = raw.raw_data.get("graph", [])

        for node in graph_nodes:
            entities = node.get("entities", [])
            for entity in entities:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Graph entity: {entity.get('name', entity.get('id', '?'))}",
                    detail={
                        "entity_id": entity.get("id", ""),
                        "entity_type": entity.get("type", ""),
                        "entity_name": entity.get("name", ""),
                        "properties": entity.get("properties", {}),
                    },
                    resource_id=entity.get("id", ""),
                    resource_type=entity.get("type", ""),
                    resource_name=entity.get("name", ""),
                    severity="info",
                ))

        return findings


# Register
registry.register(WizNormalizer())
