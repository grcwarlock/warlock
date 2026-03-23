"""FOSSA normalizer — transforms raw FOSSA API responses into Findings.

Normalizes projects as inventory, issues as vulnerability findings,
and dependencies as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_FOSSA_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class FossaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for FOSSA telemetry."""

    HANDLERS: dict[str, str] = {
        "fossa_projects": "_normalize_projects",
        "fossa_issues": "_normalize_issues",
        "fossa_dependencies": "_normalize_dependencies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fossa" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fossa",
            "source_type": SourceType.CODE,
            "provider": "fossa",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for project in raw.raw_data.get("response", []):
            project_id = str(project.get("id", project.get("locator", "")))
            title = project.get("title", project.get("name", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"FOSSA project: {title}",
                    detail={
                        "project_id": project_id,
                        "title": title,
                        "locator": project.get("locator", ""),
                        "policy": project.get("policy", {}).get("title", "")
                        if isinstance(project.get("policy"), dict)
                        else "",
                        "issue_count": project.get("issueCount", 0),
                        "last_analyzed": project.get("latestScan", ""),
                    },
                    resource_id=project_id,
                    resource_type="fossa_project",
                    resource_name=title,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for issue in raw.raw_data.get("response", []):
            issue_id = str(issue.get("id", ""))
            issue_type = issue.get("type", "unknown")
            raw_severity = issue.get("severity", "medium").lower()
            severity = _FOSSA_SEVERITY.get(raw_severity, "medium")
            rule = issue.get("rule", {})
            rule_name = rule.get("name", issue_type) if isinstance(rule, dict) else issue_type
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"FOSSA issue: {rule_name}",
                    detail={
                        "issue_id": issue_id,
                        "type": issue_type,
                        "rule": rule_name,
                        "severity": raw_severity,
                        "revision": issue.get("revision", {}).get("id", "")
                        if isinstance(issue.get("revision"), dict)
                        else "",
                        "resolved": issue.get("resolved", False),
                    },
                    resource_id=issue_id,
                    resource_type="fossa_issue",
                    resource_name=rule_name,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_dependencies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for dep in raw.raw_data.get("response", []):
            dep_id = str(dep.get("locator", dep.get("id", "")))
            name = dep.get("name", dep_id)
            version = dep.get("version", "")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"FOSSA dependency: {name}@{version}",
                    detail={
                        "locator": dep_id,
                        "name": name,
                        "version": version,
                        "license": dep.get("license", ""),
                        "direct": dep.get("direct", False),
                    },
                    resource_id=dep_id,
                    resource_type="fossa_dependency",
                    resource_name=f"{name}@{version}",
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(FossaNormalizer())
