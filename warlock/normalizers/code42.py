"""Code42 Incydr normalizer — transforms raw Code42 API responses into Findings.

Normalizes alerts and file events as DLP alert findings, users as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "NO_RISK_INDICATED": "info",
}


class Code42Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Code42 Incydr findings."""

    HANDLERS: dict[str, str] = {
        "code42_alerts": "_normalize_alerts",
        "code42_file_events": "_normalize_file_events",
        "code42_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "code42" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "code42",
            "source_type": SourceType.DLP,
            "provider": "code42",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("alerts", response.get("data", []))

        for alert in items:
            alert_id = str(alert.get("id", alert.get("alertId", "")))
            name = alert.get("name", alert.get("type", "DLP Alert"))
            severity_raw = str(alert.get("severity", "LOW")).upper()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Code42 alert: {name}",
                    detail={
                        "alert_id": alert_id,
                        "name": name,
                        "description": alert.get("description", ""),
                        "severity": severity_raw,
                        "state": alert.get("state", ""),
                        "actor": alert.get("actor", ""),
                        "target": alert.get("target", ""),
                        "created_at": alert.get("createdAt", ""),
                    },
                    resource_id=alert_id,
                    resource_type="code42_alert",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_file_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("fileEvents", response.get("data", []))

        for event in items:
            event_id = str(event.get("eventId", event.get("id", "")))
            file_name = event.get("fileName", event.get("file", {}).get("name", "unknown"))
            exposure = event.get("exposure", [])
            # Any exfiltration-related exposure is a high severity alert
            severity = "high" if any(e in str(exposure) for e in ("OUTSIDE_TRUSTED", "EXFILTRATED")) else "medium"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Code42 file event: {file_name}",
                    detail={
                        "event_id": event_id,
                        "file_name": file_name,
                        "file_path": event.get("filePath", ""),
                        "exposure": exposure,
                        "event_type": event.get("eventType", ""),
                        "actor": event.get("actor", ""),
                        "device_name": event.get("deviceName", ""),
                        "timestamp": event.get("eventTimestamp", ""),
                    },
                    resource_id=event_id,
                    resource_type="code42_file_event",
                    resource_name=file_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("users", response.get("data", []))

        for user in items:
            user_id = str(user.get("userId", user.get("id", "")))
            username = user.get("username", user.get("email", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Code42 user: {username}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "status": user.get("status", ""),
                        "org": user.get("orgName", ""),
                        "created_at": user.get("creationDate", ""),
                    },
                    resource_id=user_id,
                    resource_type="code42_user",
                    resource_name=username,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(Code42Normalizer())
