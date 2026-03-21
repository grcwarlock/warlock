"""Abnormal Security normalizer — transforms raw Abnormal Security API responses into Findings.

Handles threats (BEC, phishing, malware), cases, and abuse mailbox submissions.
Flags active BEC threats, high-severity phishing attacks, unresolved cases,
and attack campaigns targeting executives.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Threat types considered high-risk
HIGH_RISK_THREAT_TYPES = {
    "BEC",
    "CREDENTIAL_PHISHING",
    "EXTORTION",
    "INVOICE_FRAUD",
    "PAYLOAD",
    "SCAM",
}

# VIP / executive title patterns
EXECUTIVE_TITLES = {
    "ceo",
    "cfo",
    "cto",
    "cio",
    "ciso",
    "coo",
    "president",
    "vice president",
    "vp",
    "director",
    "chief",
    "executive",
    "partner",
    "managing director",
    "board member",
    "chairman",
    "treasurer",
    "controller",
    "general counsel",
}


class AbnormalSecurityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "abnormal_threats": "_normalize_threats",
        "abnormal_cases": "_normalize_cases",
        "abnormal_abuse_mailbox": "_normalize_abuse_mailbox",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "abnormal_security" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Abnormal Security findings."""
        return {
            "raw_event_id": raw.id,
            "source": "abnormal_security",
            "source_type": SourceType.EMAIL,
            "provider": "abnormal_security",
            "observed_at": raw.observed_at,
        }

    # -- Threats --

    def _normalize_threats(self, raw: RawEventData) -> list[FindingData]:
        """Normalize email threats; flag BEC, high-severity phishing, executive targeting."""
        findings = []
        threats = raw.raw_data.get("threats", [])

        for threat in threats:
            threat_id = threat.get("threatId", threat.get("id", ""))
            attack_type = threat.get("attackType", "")
            attack_strategy = threat.get("attackStrategy", "")
            severity_level = threat.get("severityLevel", "")
            subject = threat.get("subject", "")
            sender_email = threat.get("senderEmail", threat.get("fromAddress", ""))
            recipient_email = threat.get("recipientEmail", threat.get("toAddress", ""))
            received_time = threat.get("receivedTime", "")
            is_read = threat.get("isRead", False)
            remediation_status = threat.get("remediationStatus", "")
            impersonated_party = threat.get("impersonatedParty", "")
            attack_vector = threat.get("attackVector", "")
            return_path = threat.get("returnPath", "")
            recipient_name = threat.get("recipientName", "")

            # Map severity
            severity_map = {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }
            severity = severity_map.get(severity_level, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Email threat: {attack_type} — {subject[:80]}",
                    detail={
                        "threat_id": threat_id,
                        "attack_type": attack_type,
                        "attack_strategy": attack_strategy,
                        "severity_level": severity_level,
                        "subject": subject,
                        "sender_email": sender_email,
                        "recipient_email": recipient_email,
                        "received_time": received_time,
                        "is_read": is_read,
                        "remediation_status": remediation_status,
                        "impersonated_party": impersonated_party,
                        "attack_vector": attack_vector,
                        "return_path": return_path,
                    },
                    resource_id=threat_id,
                    resource_type="abnormal_threat",
                    resource_name=f"{attack_type}:{threat_id[:8]}",
                    severity=severity,
                )
            )

            # Flag active BEC threats
            if attack_type == "BEC" and remediation_status != "Auto-Remediated":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Active BEC threat: {subject[:60]}",
                        detail={
                            "threat_id": threat_id,
                            "attack_type": "BEC",
                            "sender_email": sender_email,
                            "recipient_email": recipient_email,
                            "impersonated_party": impersonated_party,
                            "remediation_status": remediation_status,
                            "issue": "Business Email Compromise threat not remediated — potential financial fraud risk",
                        },
                        resource_id=threat_id,
                        resource_type="abnormal_threat",
                        resource_name=f"BEC:{threat_id[:8]}",
                        severity="critical",
                    )
                )

            # Flag high-severity phishing targeting executives
            if recipient_name and any(
                title in recipient_name.lower() for title in EXECUTIVE_TITLES
            ):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Executive-targeted attack: {attack_type} to {recipient_name}",
                        detail={
                            "threat_id": threat_id,
                            "attack_type": attack_type,
                            "recipient_name": recipient_name,
                            "recipient_email": recipient_email,
                            "sender_email": sender_email,
                            "subject": subject,
                            "issue": "Attack campaign targeting executive/VIP — elevated risk of credential compromise or fraud",
                        },
                        resource_id=threat_id,
                        resource_type="abnormal_threat",
                        resource_name=f"{attack_type}:exec:{threat_id[:8]}",
                        severity="critical",
                    )
                )

            # Flag high-risk threat types that are active
            if (
                attack_type in HIGH_RISK_THREAT_TYPES
                and severity_level == "HIGH"
                and remediation_status not in ("Auto-Remediated", "Remediated")
            ):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"High-severity active threat: {attack_type}",
                        detail={
                            "threat_id": threat_id,
                            "attack_type": attack_type,
                            "severity_level": severity_level,
                            "remediation_status": remediation_status,
                            "recipient_email": recipient_email,
                            "issue": f"High-severity {attack_type} threat not remediated",
                        },
                        resource_id=threat_id,
                        resource_type="abnormal_threat",
                        resource_name=f"{attack_type}:{threat_id[:8]}",
                        severity="high",
                    )
                )

        return findings

    # -- Cases --

    def _normalize_cases(self, raw: RawEventData) -> list[FindingData]:
        """Normalize investigation cases; flag unresolved cases."""
        findings = []
        cases = raw.raw_data.get("cases", [])

        for case in cases:
            case_id = case.get("caseId", case.get("id", ""))
            description = case.get("description", "")
            severity_level = case.get("severityLevel", case.get("severity", ""))
            status = case.get("status", "")
            threat_ids = case.get("threatIds", [])
            created_at = case.get("createdAt", case.get("customerVisibleTime", ""))
            affected_employee = case.get("affectedEmployee", "")

            severity_map = {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }
            severity = severity_map.get(severity_level, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Abnormal case: {description[:80]}",
                    detail={
                        "case_id": case_id,
                        "description": description,
                        "severity_level": severity_level,
                        "status": status,
                        "threat_ids": threat_ids,
                        "created_at": created_at,
                        "affected_employee": affected_employee,
                    },
                    resource_id=case_id,
                    resource_type="abnormal_case",
                    resource_name=f"case:{case_id}",
                    severity=severity,
                )
            )

            # Flag unresolved cases
            if status not in ("Closed", "Resolved", "CLOSED", "RESOLVED"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unresolved security case: {description[:60]}",
                        detail={
                            "case_id": case_id,
                            "description": description,
                            "severity_level": severity_level,
                            "status": status,
                            "affected_employee": affected_employee,
                            "issue": "Security investigation case is unresolved — threat may still be active",
                        },
                        resource_id=case_id,
                        resource_type="abnormal_case",
                        resource_name=f"case:{case_id}",
                        severity="high" if severity_level == "HIGH" else "medium",
                    )
                )

        return findings

    # -- Abuse Mailbox --

    def _normalize_abuse_mailbox(self, raw: RawEventData) -> list[FindingData]:
        """Normalize abuse mailbox submissions."""
        findings = []
        submissions = raw.raw_data.get("submissions", [])

        for sub in submissions:
            sub_id = sub.get("id", sub.get("submissionId", ""))
            reporter = sub.get("reporter", sub.get("reporterEmail", ""))
            subject = sub.get("subject", "")
            judgment = sub.get("judgment", sub.get("analysisResult", ""))
            attack_type = sub.get("attackType", "")
            submitted_at = sub.get("submittedTime", sub.get("reportedTime", ""))

            is_malicious = judgment in ("MALICIOUS", "SPAM", "malicious", "spam")
            severity = "high" if is_malicious else "info"

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory" if not is_malicious else "alert",
                    title=f"Abuse mailbox: {judgment} — {subject[:60]}",
                    detail={
                        "submission_id": sub_id,
                        "reporter": reporter,
                        "subject": subject,
                        "judgment": judgment,
                        "attack_type": attack_type,
                        "submitted_at": submitted_at,
                    },
                    resource_id=sub_id,
                    resource_type="abnormal_abuse_mailbox",
                    resource_name=f"abuse:{sub_id[:8]}",
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(AbnormalSecurityNormalizer())
