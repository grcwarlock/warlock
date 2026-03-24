"""Incident response playbook library and crisis communication templates.

Provides structured, phase-based playbooks for common incident types
(data breach, ransomware, insider threat, DDoS) with step-level execution
tracking via the audit trail.  Communication templates support regulatory
notification deadlines (GDPR 72h, SEC 4 business days).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "data_breach": {
        "name": "Data Breach Response",
        "description": (
            "End-to-end response for confirmed or suspected data breach "
            "involving PII, PHI, or other regulated data."
        ),
        "severity": "critical",
        "phases": [
            {
                "name": "Detection & Triage",
                "steps": [
                    {
                        "role": "Security Analyst",
                        "action": "Confirm breach indicators and classify data types affected",
                        "timeframe": "0-1 hours",
                        "checklist": [
                            "Identify data types exposed (PII, PHI, PCI, credentials)",
                            "Determine number of affected records",
                            "Identify attack vector and entry point",
                            "Check if exfiltration is ongoing",
                        ],
                    },
                    {
                        "role": "Incident Commander",
                        "action": "Activate incident response team and establish war room",
                        "timeframe": "0-1 hours",
                        "checklist": [
                            "Page on-call responders",
                            "Open dedicated communication channel",
                            "Assign roles (IC, scribe, comms lead)",
                            "Begin incident timeline documentation",
                        ],
                    },
                ],
            },
            {
                "name": "Containment",
                "steps": [
                    {
                        "role": "Security Engineer",
                        "action": "Isolate affected systems and revoke compromised credentials",
                        "timeframe": "1-4 hours",
                        "checklist": [
                            "Block attacker IP addresses and domains",
                            "Disable compromised user accounts",
                            "Rotate affected API keys and tokens",
                            "Segment network to prevent lateral movement",
                        ],
                    },
                    {
                        "role": "Forensics Lead",
                        "action": "Preserve evidence and begin forensic imaging",
                        "timeframe": "1-4 hours",
                        "checklist": [
                            "Capture memory dumps of affected systems",
                            "Image affected disks before remediation",
                            "Preserve relevant log files with chain of custody",
                            "Document all containment actions taken",
                        ],
                    },
                ],
            },
            {
                "name": "Notification",
                "steps": [
                    {
                        "role": "Legal / Privacy Officer",
                        "action": "Assess regulatory notification obligations",
                        "timeframe": "4-24 hours",
                        "checklist": [
                            "Determine applicable regulations (GDPR, HIPAA, state laws)",
                            "Calculate notification deadlines (GDPR: 72h, HIPAA: 60 days)",
                            "Draft regulatory notification using approved template",
                            "Prepare affected individual notification letters",
                        ],
                    },
                    {
                        "role": "Communications Lead",
                        "action": "Issue stakeholder notifications",
                        "timeframe": "24-72 hours",
                        "checklist": [
                            "Notify executive leadership",
                            "Send initial notification to affected individuals",
                            "Prepare public statement if required",
                            "Brief customer support team on expected inquiries",
                        ],
                    },
                ],
            },
            {
                "name": "Recovery & Lessons Learned",
                "steps": [
                    {
                        "role": "Engineering Lead",
                        "action": "Remediate root cause and harden affected systems",
                        "timeframe": "1-7 days",
                        "checklist": [
                            "Patch exploited vulnerability",
                            "Deploy additional monitoring on affected systems",
                            "Verify clean state of all affected hosts",
                            "Restore from verified clean backups if needed",
                        ],
                    },
                    {
                        "role": "Incident Commander",
                        "action": "Conduct post-incident review and update playbook",
                        "timeframe": "7-14 days",
                        "checklist": [
                            "Hold blameless post-mortem with all responders",
                            "Document root cause, timeline, and impact",
                            "Create action items for prevention",
                            "Update this playbook with lessons learned",
                        ],
                    },
                ],
            },
        ],
    },
    "ransomware": {
        "name": "Ransomware Response",
        "description": (
            "Response procedure for ransomware infection including containment, "
            "recovery from backups, and law enforcement coordination."
        ),
        "severity": "critical",
        "phases": [
            {
                "name": "Detection & Isolation",
                "steps": [
                    {
                        "role": "Security Analyst",
                        "action": "Identify ransomware variant and scope of encryption",
                        "timeframe": "0-1 hours",
                        "checklist": [
                            "Identify ransomware strain from ransom note or file extension",
                            "Determine encryption scope (files, drives, network shares)",
                            "Check for known decryptors on nomoreransom.org",
                            "Assess whether data exfiltration preceded encryption",
                        ],
                    },
                    {
                        "role": "Network Engineer",
                        "action": "Isolate infected systems from network immediately",
                        "timeframe": "0-1 hours",
                        "checklist": [
                            "Disconnect infected machines from network (do not power off)",
                            "Block C2 domains and IPs at firewall",
                            "Disable shared drives and network mounts",
                            "Verify backup systems are isolated and unaffected",
                        ],
                    },
                ],
            },
            {
                "name": "Assessment & Decision",
                "steps": [
                    {
                        "role": "Incident Commander",
                        "action": "Assess business impact and recovery options",
                        "timeframe": "1-4 hours",
                        "checklist": [
                            "Inventory affected systems and data criticality",
                            "Verify backup integrity and coverage",
                            "Estimate recovery time from backups vs other options",
                            "Engage legal counsel on ransom payment implications",
                        ],
                    },
                    {
                        "role": "Legal / CISO",
                        "action": "Coordinate with law enforcement",
                        "timeframe": "1-8 hours",
                        "checklist": [
                            "Report to FBI IC3 or local CERT",
                            "Engage cyber insurance carrier",
                            "Document chain of custody for all evidence",
                            "Assess OFAC sanctions risk if considering payment",
                        ],
                    },
                ],
            },
            {
                "name": "Recovery",
                "steps": [
                    {
                        "role": "Engineering Lead",
                        "action": "Restore systems from clean backups",
                        "timeframe": "1-7 days",
                        "checklist": [
                            "Verify backup integrity before restoration",
                            "Rebuild affected systems from known-good images",
                            "Restore data from most recent clean backup",
                            "Validate restored systems before reconnecting to network",
                        ],
                    },
                    {
                        "role": "Security Engineer",
                        "action": "Harden environment against reinfection",
                        "timeframe": "1-14 days",
                        "checklist": [
                            "Reset all credentials across the domain",
                            "Patch initial access vector",
                            "Deploy EDR on all endpoints",
                            "Implement network segmentation improvements",
                        ],
                    },
                ],
            },
        ],
    },
    "insider_threat": {
        "name": "Insider Threat Response",
        "description": (
            "Response to confirmed or suspected malicious insider activity "
            "including data theft, sabotage, or unauthorized access."
        ),
        "severity": "high",
        "phases": [
            {
                "name": "Detection & Verification",
                "steps": [
                    {
                        "role": "Security Analyst",
                        "action": "Verify anomalous activity and correlate indicators",
                        "timeframe": "0-4 hours",
                        "checklist": [
                            "Review DLP alerts and data access logs",
                            "Correlate with badge access and VPN logs",
                            "Check for unusual after-hours access patterns",
                            "Verify with HR whether employee is on notice or PIP",
                        ],
                    },
                    {
                        "role": "Legal / HR",
                        "action": "Assess legal constraints and coordinate response",
                        "timeframe": "0-4 hours",
                        "checklist": [
                            "Review employment agreement and NDA terms",
                            "Confirm investigation does not violate employee rights",
                            "Engage legal counsel for evidence preservation guidance",
                            "Coordinate with HR on employee status and access",
                        ],
                    },
                ],
            },
            {
                "name": "Containment & Investigation",
                "steps": [
                    {
                        "role": "Security Engineer",
                        "action": "Restrict access without alerting the subject",
                        "timeframe": "4-24 hours",
                        "checklist": [
                            "Enable enhanced monitoring on subject accounts",
                            "Restrict access to sensitive systems silently",
                            "Preserve all email and messaging archives",
                            "Image subject workstation if possible",
                        ],
                    },
                    {
                        "role": "Forensics Lead",
                        "action": "Conduct forensic investigation of activity",
                        "timeframe": "1-7 days",
                        "checklist": [
                            "Analyze data access and exfiltration patterns",
                            "Review USB and removable media usage logs",
                            "Check cloud storage and personal email forwarding",
                            "Document all findings with timestamps and evidence hashes",
                        ],
                    },
                ],
            },
            {
                "name": "Resolution",
                "steps": [
                    {
                        "role": "HR / Legal",
                        "action": "Execute termination and access revocation",
                        "timeframe": "1-2 days",
                        "checklist": [
                            "Coordinate termination with legal and management",
                            "Revoke all system access simultaneously",
                            "Collect company devices and badges",
                            "Issue litigation hold if warranted",
                        ],
                    },
                    {
                        "role": "Incident Commander",
                        "action": "Close investigation and implement preventive controls",
                        "timeframe": "7-30 days",
                        "checklist": [
                            "Complete investigation report with findings",
                            "Review and strengthen DLP policies",
                            "Update access review procedures",
                            "Brief leadership on outcome and recommendations",
                        ],
                    },
                ],
            },
        ],
    },
    "ddos": {
        "name": "DDoS Attack Response",
        "description": (
            "Response to distributed denial-of-service attacks targeting "
            "availability of customer-facing or internal services."
        ),
        "severity": "high",
        "phases": [
            {
                "name": "Detection & Classification",
                "steps": [
                    {
                        "role": "NOC Analyst",
                        "action": "Classify attack type and identify targets",
                        "timeframe": "0-15 minutes",
                        "checklist": [
                            "Identify attack type (volumetric, protocol, application layer)",
                            "Determine targeted services and endpoints",
                            "Measure attack bandwidth and request rate",
                            "Check if attack is a diversion for another intrusion",
                        ],
                    },
                    {
                        "role": "Incident Commander",
                        "action": "Activate DDoS response team and notify stakeholders",
                        "timeframe": "0-30 minutes",
                        "checklist": [
                            "Page on-call network and security engineers",
                            "Notify affected service owners",
                            "Update status page to acknowledge degradation",
                            "Open communication bridge for responders",
                        ],
                    },
                ],
            },
            {
                "name": "Mitigation",
                "steps": [
                    {
                        "role": "Network Engineer",
                        "action": "Engage DDoS mitigation services and apply filters",
                        "timeframe": "15-60 minutes",
                        "checklist": [
                            "Activate cloud DDoS protection (AWS Shield, Cloudflare, Akamai)",
                            "Apply rate limiting and geo-blocking where appropriate",
                            "Enable WAF rules for application-layer attacks",
                            "Reroute traffic through scrubbing centers if needed",
                        ],
                    },
                    {
                        "role": "Platform Engineer",
                        "action": "Scale infrastructure to absorb residual traffic",
                        "timeframe": "15-60 minutes",
                        "checklist": [
                            "Scale out application tier (auto-scaling groups)",
                            "Increase CDN cache TTLs to reduce origin load",
                            "Enable circuit breakers on downstream dependencies",
                            "Monitor service health during mitigation",
                        ],
                    },
                ],
            },
            {
                "name": "Recovery & Hardening",
                "steps": [
                    {
                        "role": "Network Engineer",
                        "action": "Confirm attack has subsided and restore normal operations",
                        "timeframe": "1-24 hours",
                        "checklist": [
                            "Verify traffic patterns have returned to normal",
                            "Gradually remove emergency mitigation rules",
                            "Update status page to confirm resolution",
                            "Collect ISP and CDN reports for documentation",
                        ],
                    },
                    {
                        "role": "Security Engineer",
                        "action": "Harden defenses and update runbooks",
                        "timeframe": "1-7 days",
                        "checklist": [
                            "Review and update DDoS mitigation thresholds",
                            "Implement permanent rate-limiting improvements",
                            "Update runbooks with attack specifics",
                            "Conduct post-mortem and share learnings",
                        ],
                    },
                ],
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# Communication templates
# ---------------------------------------------------------------------------

COMMUNICATION_TEMPLATES: dict[str, dict[str, str]] = {
    "initial_notification": {
        "name": "Initial Stakeholder Notification",
        "subject": "INCIDENT ALERT: {incident_title} [{severity}]",
        "body": (
            "This message is to inform you that a {severity} security incident "
            "has been identified.\n\n"
            "Incident ID: {incident_id}\n"
            "Title: {incident_title}\n"
            "Classification: {classification}\n"
            "Severity: {severity}\n"
            "Detected at: {detected_at}\n"
            "Incident Commander: {commander}\n\n"
            "Current Status: {status}\n\n"
            "Summary:\n{description}\n\n"
            "Next update will be provided within {update_interval}.\n\n"
            "If you have relevant information, contact the incident response "
            "team at {contact}."
        ),
    },
    "status_update": {
        "name": "Incident Status Update",
        "subject": "UPDATE #{update_number}: {incident_title} [{severity}]",
        "body": (
            "Incident Status Update #{update_number}\n"
            "{'=' * 40}\n\n"
            "Incident ID: {incident_id}\n"
            "Title: {incident_title}\n"
            "Severity: {severity}\n"
            "Current Status: {status}\n"
            "Time Elapsed: {elapsed}\n\n"
            "Progress Since Last Update:\n{progress}\n\n"
            "Current Actions:\n{current_actions}\n\n"
            "Next Steps:\n{next_steps}\n\n"
            "Next update expected: {next_update_time}\n\n"
            "Incident Commander: {commander}"
        ),
    },
    "resolution_notice": {
        "name": "Incident Resolution Notice",
        "subject": "RESOLVED: {incident_title} [{severity}]",
        "body": (
            "This incident has been resolved.\n\n"
            "Incident ID: {incident_id}\n"
            "Title: {incident_title}\n"
            "Severity: {severity}\n"
            "Duration: {duration}\n"
            "Detected: {detected_at}\n"
            "Resolved: {resolved_at}\n\n"
            "Root Cause:\n{root_cause}\n\n"
            "Resolution:\n{resolution}\n\n"
            "Impact Summary:\n{impact_summary}\n\n"
            "Preventive Measures:\n{preventive_measures}\n\n"
            "A full post-mortem report will be distributed within {postmortem_deadline}."
        ),
    },
    "regulatory_notification": {
        "name": "Regulatory Body Notification",
        "subject": "Data Breach Notification - {organization} - {incident_id}",
        "body": (
            "REGULATORY NOTIFICATION\n"
            "{'=' * 40}\n\n"
            "Reporting Organization: {organization}\n"
            "Contact: {contact_name}, {contact_title}\n"
            "Email: {contact_email}\n"
            "Phone: {contact_phone}\n\n"
            "Date of Discovery: {discovery_date}\n"
            "Date of Notification: {notification_date}\n"
            "Notification Deadline: {deadline}\n\n"
            "Applicable Regulation: {regulation}\n"
            "GDPR Article 33 deadline: 72 hours from discovery\n"
            "SEC Rule 10-K/8-K deadline: 4 business days from materiality determination\n\n"
            "Nature of Breach:\n{breach_description}\n\n"
            "Categories of Data Affected:\n{data_categories}\n\n"
            "Approximate Number of Affected Individuals: {affected_count}\n\n"
            "Likely Consequences:\n{consequences}\n\n"
            "Measures Taken:\n{measures_taken}\n\n"
            "Measures Proposed:\n{measures_proposed}\n\n"
            "Reference: {incident_id}"
        ),
    },
}


# ---------------------------------------------------------------------------
# Playbook library class
# ---------------------------------------------------------------------------


class PlaybookLibrary:
    """Manages incident response playbooks and step execution tracking."""

    def __init__(self) -> None:
        self._playbooks = PLAYBOOKS

    def list_playbooks(self) -> list[dict[str, str]]:
        """Return summary list of all available playbooks."""
        return [
            {
                "type": pb_type,
                "name": pb["name"],
                "description": pb["description"],
                "severity": pb["severity"],
                "phase_count": len(pb["phases"]),
                "total_steps": sum(len(p["steps"]) for p in pb["phases"]),
            }
            for pb_type, pb in self._playbooks.items()
        ]

    def get_playbook(self, incident_type: str) -> dict[str, Any] | None:
        """Return the full playbook for a given incident type, or None."""
        return self._playbooks.get(incident_type)

    def execute_step(
        self,
        session: Session,
        incident_id: str,
        playbook_type: str,
        phase_index: int,
        step_index: int,
        actor: str,
    ) -> dict[str, Any]:
        """Mark a playbook step as completed and record in audit trail.

        Returns a dict with execution details.
        """
        from warlock.db.models import AuditEntry

        playbook = self._playbooks.get(playbook_type)
        if not playbook:
            raise ValueError(f"Unknown playbook type: {playbook_type}")

        if phase_index < 0 or phase_index >= len(playbook["phases"]):
            raise ValueError(
                f"Phase index {phase_index} out of range (0-{len(playbook['phases']) - 1})"
            )

        phase = playbook["phases"][phase_index]
        if step_index < 0 or step_index >= len(phase["steps"]):
            raise ValueError(f"Step index {step_index} out of range (0-{len(phase['steps']) - 1})")

        step = phase["steps"][step_index]
        now = datetime.now(timezone.utc)

        # Record in audit trail
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:playbook_step_completed:{incident_id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="playbook_step_completed",
            entity_type="issue",
            entity_id=incident_id,
            actor=actor,
            extra={
                "playbook_type": playbook_type,
                "phase_index": phase_index,
                "phase_name": phase["name"],
                "step_index": step_index,
                "step_role": step["role"],
                "step_action": step["action"],
            },
            created_at=now,
        )
        session.add(audit)
        session.flush()

        return {
            "playbook_type": playbook_type,
            "phase": phase["name"],
            "step": step["action"],
            "role": step["role"],
            "completed_by": actor,
            "completed_at": now.isoformat(),
            "audit_sequence": seq,
        }

    def get_progress(
        self,
        session: Session,
        incident_id: str,
        playbook_type: str,
    ) -> dict[str, Any]:
        """Return playbook execution progress for an incident.

        Queries the audit trail for completed steps and returns a
        structured progress report.
        """
        from warlock.db.models import AuditEntry

        playbook = self._playbooks.get(playbook_type)
        if not playbook:
            raise ValueError(f"Unknown playbook type: {playbook_type}")

        # Find all completed steps from audit trail
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_id == incident_id,
                AuditEntry.action == "playbook_step_completed",
            )
            .order_by(AuditEntry.created_at.asc())
            .all()
        )

        completed: set[tuple[int, int]] = set()
        completion_details: dict[tuple[int, int], dict] = {}
        for e in entries:
            extra = e.extra or {}
            if extra.get("playbook_type") == playbook_type:
                key = (extra.get("phase_index", -1), extra.get("step_index", -1))
                completed.add(key)
                completion_details[key] = {
                    "actor": e.actor,
                    "completed_at": ensure_aware(e.created_at).isoformat()
                    if e.created_at
                    else None,
                }

        total_steps = sum(len(p["steps"]) for p in playbook["phases"])
        completed_count = len(completed)

        phases_progress = []
        for pi, phase in enumerate(playbook["phases"]):
            steps_progress = []
            for si, step in enumerate(phase["steps"]):
                key = (pi, si)
                is_done = key in completed
                step_info: dict[str, Any] = {
                    "step_index": si,
                    "role": step["role"],
                    "action": step["action"],
                    "timeframe": step["timeframe"],
                    "completed": is_done,
                }
                if is_done:
                    step_info.update(completion_details[key])
                steps_progress.append(step_info)

            phase_done = sum(1 for s in steps_progress if s["completed"])
            phases_progress.append(
                {
                    "phase_index": pi,
                    "phase_name": phase["name"],
                    "steps": steps_progress,
                    "completed_steps": phase_done,
                    "total_steps": len(phase["steps"]),
                }
            )

        return {
            "playbook_type": playbook_type,
            "playbook_name": playbook["name"],
            "incident_id": incident_id,
            "total_steps": total_steps,
            "completed_steps": completed_count,
            "remaining_steps": total_steps - completed_count,
            "percent_complete": round(
                (completed_count / total_steps * 100) if total_steps > 0 else 0, 1
            ),
            "phases": phases_progress,
        }


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


def render_template(template_name: str, context: dict[str, str]) -> dict[str, str]:
    """Render a communication template with the given context.

    Parameters
    ----------
    template_name:
        Key into COMMUNICATION_TEMPLATES (e.g. "initial_notification").
    context:
        Dict of placeholder values.  Missing keys are replaced with
        ``"[NOT PROVIDED]"`` to make gaps visible.

    Returns
    -------
    dict with keys ``name``, ``subject``, ``body`` (all rendered).
    """
    template = COMMUNICATION_TEMPLATES.get(template_name)
    if not template:
        available = ", ".join(sorted(COMMUNICATION_TEMPLATES.keys()))
        raise ValueError(f"Unknown template: {template_name}. Available: {available}")

    class SafeDict(dict):
        """Dict that returns a placeholder for missing keys."""

        def __missing__(self, key: str) -> str:
            return "[NOT PROVIDED]"

    safe = SafeDict(context)

    return {
        "name": template["name"],
        "subject": template["subject"].format_map(safe),
        "body": template["body"].format_map(safe),
    }
