"""Proofpoint normalizer — transforms raw Proofpoint TAP API responses into Findings.

Normalizes blocked messages (count summary), delivered threats (severity from
threat score), and blocked clicks into inventory and alert findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ProofpointNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "proofpoint_blocked_messages": "_normalize_blocked_messages",
        "proofpoint_delivered_threats": "_normalize_delivered_threats",
        "proofpoint_clicks_blocked": "_normalize_clicks_blocked",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "proofpoint" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Proofpoint findings."""
        return {
            "raw_event_id": raw.id,
            "source": "proofpoint",
            "source_type": SourceType.EMAIL,
            "provider": "proofpoint",
            "observed_at": raw.observed_at,
        }

    # -- Blocked Messages --

    def _normalize_blocked_messages(self, raw: RawEventData) -> list[FindingData]:
        """Inventory finding with count summary of blocked messages."""
        messages = raw.raw_data.get("response", [])
        total = len(messages)

        # Summary finding
        findings = [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Proofpoint — {total} blocked message(s) in last 24h",
                detail={
                    "total_blocked": total,
                    "sample_subjects": [msg.get("subject", "")[:80] for msg in messages[:10]],
                },
                resource_id="proofpoint:blocked_messages",
                resource_type="email_blocked",
                resource_name="blocked-messages-summary",
                severity="info",
            )
        ]

        return findings

    # -- Delivered Threats --

    def _normalize_delivered_threats(self, raw: RawEventData) -> list[FindingData]:
        """One alert finding per delivered threat; severity from threat score."""
        findings = []
        messages = raw.raw_data.get("response", [])

        for msg in messages:
            msg_id = msg.get("GUID", msg.get("messageID", ""))
            subject = msg.get("subject", "")[:120]
            sender = msg.get("sender", msg.get("fromAddress", ""))
            recipient = msg.get("recipient", "")
            if isinstance(recipient, list):
                recipient = ", ".join(recipient[:5])

            # Extract threat score from threatsInfoMap
            threats = msg.get("threatsInfoMap", msg.get("threats", []))
            max_score = 0
            threat_details = []
            if isinstance(threats, dict):
                for threat_key, threat_info in threats.items():
                    score = threat_info.get("threatScore", threat_info.get("score", 0)) or 0
                    max_score = max(max_score, int(score))
                    threat_details.append(
                        {
                            "type": threat_key,
                            "score": score,
                            "classification": threat_info.get("classification", ""),
                        }
                    )
            elif isinstance(threats, list):
                for threat_info in threats:
                    score = threat_info.get("threatScore", threat_info.get("score", 0)) or 0
                    max_score = max(max_score, int(score))
                    threat_details.append(
                        {
                            "type": threat_info.get("threatType", ""),
                            "score": score,
                            "classification": threat_info.get("classification", ""),
                        }
                    )

            # Severity from threat score
            if max_score > 75:
                severity = "high"
            elif max_score > 50:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Delivered threat: {subject}"
                    if subject
                    else f"Delivered threat from {sender}",
                    detail={
                        "message_id": msg_id,
                        "subject": subject,
                        "sender": sender,
                        "recipient": recipient,
                        "threat_score": max_score,
                        "threats": threat_details,
                    },
                    resource_id=f"proofpoint:threat:{msg_id}",
                    resource_type="email_threat",
                    resource_name=f"threat-{msg_id[:16]}",
                    severity=severity,
                )
            )

        return findings

    # -- Clicks Blocked --

    def _normalize_clicks_blocked(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per blocked click."""
        findings = []
        clicks = raw.raw_data.get("response", [])

        for click in clicks:
            click_id = click.get("GUID", click.get("id", ""))
            url = click.get("url", "")[:200]
            sender = click.get("sender", "")
            recipient = click.get("recipient", "")
            click_time = click.get("clickTime", "")
            threat_status = click.get("threatStatus", click.get("classification", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Blocked click: {recipient} on {url[:60]}",
                    detail={
                        "click_id": click_id,
                        "url": url,
                        "sender": sender,
                        "recipient": recipient,
                        "click_time": click_time,
                        "threat_status": threat_status,
                    },
                    resource_id=f"proofpoint:click:{click_id}",
                    resource_type="email_click_blocked",
                    resource_name=f"click-{click_id[:16]}",
                    severity="info",
                )
            )

        return findings


# Register
registry.register(ProofpointNormalizer())
