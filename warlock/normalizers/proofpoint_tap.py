"""Proofpoint TAP normalizer — transforms extended TAP API responses into Findings.

Handles permitted clicks, blocked/delivered messages, and TAP issues.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ProofpointTAPNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Proofpoint TAP data."""

    HANDLERS: dict[str, str] = {
        "proofpoint_tap_clicks_permitted": "_normalize_clicks_permitted",
        "proofpoint_tap_messages_blocked": "_normalize_messages_blocked",
        "proofpoint_tap_messages_delivered": "_normalize_messages_delivered",
        "proofpoint_tap_issues": "_normalize_issues",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "proofpoint_tap" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "proofpoint_tap",
            "source_type": SourceType.EMAIL_SECURITY,
            "provider": "proofpoint_tap",
            "observed_at": raw.observed_at,
        }

    def _normalize_clicks_permitted(self, raw: RawEventData) -> list[FindingData]:
        """Alert for each permitted click on a malicious URL."""
        findings: list[FindingData] = []
        clicks = raw.raw_data.get("response", [])

        for click in clicks:
            click_id = click.get("GUID", click.get("id", ""))
            url = click.get("url", "")[:200]
            recipient = click.get("recipient", "")
            threat_status = click.get("threatStatus", "")

            severity = "high" if threat_status in ("active", "malicious") else "medium"
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Permitted click: {recipient} on {url[:60]}",
                    detail={
                        "click_id": click_id,
                        "url": url,
                        "recipient": recipient,
                        "threat_status": threat_status,
                    },
                    resource_id=f"proofpoint_tap:click:{click_id}",
                    resource_type="email_click_permitted",
                    resource_name=f"click-{click_id[:16]}",
                    severity=severity,
                )
            )

        return findings

    def _normalize_messages_blocked(self, raw: RawEventData) -> list[FindingData]:
        """Inventory of blocked messages."""
        messages = raw.raw_data.get("response", [])
        total = len(messages)
        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Proofpoint TAP — {total} blocked message(s) in last 24h",
                detail={
                    "total_blocked": total,
                    "sample_subjects": [m.get("subject", "")[:80] for m in messages[:10]],
                },
                resource_id="proofpoint_tap:blocked_messages",
                resource_type="email_blocked",
                resource_name="tap-blocked-messages-summary",
                severity="info",
            )
        ]

    def _normalize_messages_delivered(self, raw: RawEventData) -> list[FindingData]:
        """Alert for each delivered threat message."""
        findings: list[FindingData] = []
        messages = raw.raw_data.get("response", [])

        for msg in messages:
            msg_id = msg.get("GUID", msg.get("messageID", ""))
            subject = msg.get("subject", "")[:120]
            sender = msg.get("sender", msg.get("fromAddress", ""))
            threat_score = 0
            threats = msg.get("threatsInfoMap", msg.get("threats", []))
            if isinstance(threats, dict):
                for info in threats.values():
                    score = info.get("threatScore", 0) or 0
                    threat_score = max(threat_score, int(score))
            elif isinstance(threats, list):
                for info in threats:
                    score = info.get("threatScore", 0) or 0
                    threat_score = max(threat_score, int(score))

            severity = "high" if threat_score > 75 else "medium" if threat_score > 50 else "low"
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"TAP delivered threat: {subject}"
                    if subject
                    else f"TAP threat from {sender}",
                    detail={
                        "message_id": msg_id,
                        "subject": subject,
                        "sender": sender,
                        "threat_score": threat_score,
                    },
                    resource_id=f"proofpoint_tap:threat:{msg_id}",
                    resource_type="email_threat",
                    resource_name=f"tap-threat-{msg_id[:16]}",
                    severity=severity,
                )
            )

        return findings

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        """Inventory of TAP issues/campaigns."""
        issues = raw.raw_data.get("response", [])
        total = len(issues)
        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Proofpoint TAP — {total} active issue(s)",
                detail={
                    "total_issues": total,
                    "issue_ids": [i.get("id", "") for i in issues[:20]],
                },
                resource_id="proofpoint_tap:issues",
                resource_type="email_issues",
                resource_name="tap-issues-summary",
                severity="info",
            )
        ]


registry.register(ProofpointTAPNormalizer())
