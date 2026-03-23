"""Socket.dev normalizer — transforms raw Socket Security API responses into Findings.

Normalizes repos as inventory, alerts as vulnerability findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SOCKET_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class SocketdevNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Socket.dev telemetry."""

    HANDLERS: dict[str, str] = {
        "socketdev_repos": "_normalize_repos",
        "socketdev_alerts": "_normalize_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "socketdev" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "socketdev",
            "source_type": SourceType.CODE,
            "provider": "socketdev",
            "account_id": raw.raw_data.get("org_slug", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_repos(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for repo in raw.raw_data.get("response", []):
            repo_id = str(repo.get("id", repo.get("name", "")))
            name = repo.get("name", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Socket.dev repo: {name}",
                    detail={
                        "repo_id": repo_id,
                        "name": name,
                        "visibility": repo.get("visibility", ""),
                        "default_branch": repo.get("defaultBranch", ""),
                        "last_push": repo.get("updatedAt", ""),
                        "alert_count": repo.get("alertCount", 0),
                    },
                    resource_id=repo_id,
                    resource_type="socketdev_repo",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for alert in raw.raw_data.get("response", []):
            alert_id = str(alert.get("id", ""))
            alert_type = alert.get("type", "")
            raw_severity = alert.get("severity", "medium").lower()
            severity = _SOCKET_SEVERITY.get(raw_severity, "medium")
            pkg = alert.get("package", {})
            pkg_name = pkg.get("name", "") if isinstance(pkg, dict) else str(pkg)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Socket.dev alert: {alert_type} in {pkg_name}",
                    detail={
                        "alert_id": alert_id,
                        "type": alert_type,
                        "severity": raw_severity,
                        "package": pkg_name,
                        "package_version": pkg.get("version", "") if isinstance(pkg, dict) else "",
                        "description": alert.get("description", ""),
                        "created_at": alert.get("createdAt", ""),
                    },
                    resource_id=alert_id,
                    resource_type="socketdev_alert",
                    resource_name=f"{alert_type}/{pkg_name}",
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(SocketdevNormalizer())
