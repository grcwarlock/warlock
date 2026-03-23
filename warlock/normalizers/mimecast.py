"""Mimecast normalizer — transforms raw Mimecast API responses into Findings.

Normalizes URL threat logs as alerts, attachment threat logs as alerts,
and audit events as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_ACTION_SEVERITY: dict[str, str] = {
    "block": "high",
    "blocked": "high",
    "hold": "medium",
    "warn": "medium",
    "log": "low",
    "permit": "info",
    "allow": "info",
}


class MimecastNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Mimecast telemetry."""

    HANDLERS: dict[str, str] = {
        "mimecast_url_logs": "_normalize_url_logs",
        "mimecast_attachment_logs": "_normalize_attachment_logs",
        "mimecast_audit_events": "_normalize_audit_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "mimecast" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "mimecast",
            "source_type": SourceType.EMAIL_SECURITY,
            "provider": "mimecast",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_url_logs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for entry in raw.raw_data.get("response", []):
            url = entry.get("url", "")
            action = entry.get("action", "")
            sender = entry.get("fromHeader", entry.get("sender", ""))
            severity = _ACTION_SEVERITY.get(action.lower(), "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Mimecast URL threat: {action} — {url[:80]}",
                    detail={
                        "url": url,
                        "action": action,
                        "sender": sender,
                        "recipient": entry.get("to", ""),
                        "date": entry.get("date", ""),
                        "scan_result": entry.get("scanResult", ""),
                    },
                    resource_id=url,
                    resource_type="mimecast_url_threat",
                    resource_name=url[:120],
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_attachment_logs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for entry in raw.raw_data.get("response", []):
            filename = entry.get("filename", entry.get("fileName", ""))
            action = entry.get("action", "")
            result = entry.get("result", "")
            severity = _ACTION_SEVERITY.get(action.lower(), "medium")
            entry_id = entry.get("id", filename)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Mimecast attachment threat: {filename}",
                    detail={
                        "filename": filename,
                        "action": action,
                        "result": result,
                        "sender": entry.get("fromHeader", ""),
                        "recipient": entry.get("to", ""),
                        "date": entry.get("date", ""),
                        "file_type": entry.get("fileType", ""),
                    },
                    resource_id=str(entry_id),
                    resource_type="mimecast_attachment_threat",
                    resource_name=filename,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_audit_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for event in raw.raw_data.get("response", []):
            event_id = str(event.get("id", ""))
            action = event.get("auditType", event.get("action", ""))
            user = event.get("user", event.get("Actor", ""))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Mimecast audit: {action}",
                    detail={
                        "event_id": event_id,
                        "action": action,
                        "user": user,
                        "date": event.get("eventTime", event.get("date", "")),
                        "category": event.get("category", ""),
                    },
                    resource_id=event_id,
                    resource_type="mimecast_audit_event",
                    resource_name=action,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(MimecastNormalizer())
