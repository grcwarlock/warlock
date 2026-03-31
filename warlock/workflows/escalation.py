"""Escalation chain engine for overdue POAMs and Issues.

Scans for overdue items (past due_date), matches them against active
EscalationPolicy records, and sends notifications at the appropriate
escalation level based on how far past due the item is.

Each escalation level defines a ``delay_hours`` threshold: if the item
is overdue by more than that many hours AND the entity has not yet been
escalated to that level, a notification is sent and the entity's
``escalation_level`` / ``escalation_sent_at`` are updated.

Usage::

    from warlock.db.engine import get_session
    from warlock.workflows.escalation import EscalationManager

    mgr = EscalationManager()
    with get_session() as session:
        results = mgr.scan_overdue(session)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.config import get_settings
from warlock.db.audit import AuditTrail
from warlock.db.models import POAM, EscalationPolicy, Issue
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Severity ordering for min_severity filtering
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "moderate": 1,
    "high": 2,
    "critical": 3,
}

# Entity types that support escalation tracking fields
_ESCALATION_ENTITY_MAP: dict[str, type] = {
    "poam": POAM,
    "issue": Issue,
}


@dataclass
class EscalationEvent:
    """Result of a single escalation action."""

    entity_type: str
    entity_id: str
    policy_name: str
    previous_level: int
    new_level: int
    role: str
    delay_hours: int
    hours_overdue: float
    notified: bool
    error: str = ""


@dataclass
class EscalationStatus:
    """Current escalation state for an entity."""

    entity_type: str
    entity_id: str
    current_level: int
    last_escalated_at: datetime | None
    policy_name: str | None
    history: list[dict[str, Any]] = field(default_factory=list)


class EscalationManager:
    """Manages escalation chains for overdue POAMs and Issues.

    Works with :class:`~warlock.db.models.EscalationPolicy` to determine
    which notification level to trigger based on how far past due an item is.
    """

    def scan_overdue(self, session: Session) -> list[EscalationEvent]:
        """Find all overdue items and escalate according to active policies.

        Scans both POAMs (using ``scheduled_completion``) and Issues (using
        ``due_date``) that are past their deadline and not in a terminal
        status. Each overdue item is matched against active escalation
        policies based on entity type and severity.

        Args:
            session: Active SQLAlchemy session. The caller is responsible
                for committing the transaction.

        Returns:
            List of EscalationEvent describing every escalation action taken.
        """
        settings = get_settings()
        if not settings.escalation_enabled:
            log.debug("Escalation disabled via config — skipping scan")
            return []

        now = datetime.now(timezone.utc)

        # Load all active policies once
        policies = session.query(EscalationPolicy).filter(EscalationPolicy.active.is_(True)).all()
        if not policies:
            log.debug("No active escalation policies found")
            return []

        events: list[EscalationEvent] = []

        # Scan POAMs
        poam_events = self._scan_poams(session, policies, now)
        events.extend(poam_events)

        # Scan Issues
        issue_events = self._scan_issues(session, policies, now)
        events.extend(issue_events)

        if events:
            session.flush()
            log.info(
                "Escalation scan complete: %d escalation(s) triggered",
                len(events),
            )

        return events

    def escalate(
        self,
        session: Session,
        entity: POAM | Issue,
        entity_type: str,
        policy: EscalationPolicy,
        target_level: dict[str, Any],
        hours_overdue: float,
    ) -> EscalationEvent:
        """Send notification and update escalation state on an entity.

        Determines the notification channel from the escalation level
        configuration, sends the alert, and records the action in the
        audit trail.

        Args:
            session: Active SQLAlchemy session.
            entity: The POAM or Issue being escalated.
            entity_type: ``"poam"`` or ``"issue"``.
            policy: The matched EscalationPolicy.
            target_level: The level dict from the policy's levels JSON,
                e.g. ``{"level": 2, "role": "team_lead", "delay_hours": 48}``.
            hours_overdue: How many hours past due the entity is.

        Returns:
            EscalationEvent describing the outcome.
        """
        level_num = target_level.get("level", 1)
        role = target_level.get("role", "unknown")
        delay_hours = target_level.get("delay_hours", 24)
        notify_email = target_level.get("email", "")

        previous_level = self._get_current_level(entity, entity_type)
        now = datetime.now(timezone.utc)

        # Send notification
        notified = False
        error = ""
        if notify_email:
            notified, error = self._send_escalation_email(
                entity=entity,
                entity_type=entity_type,
                policy=policy,
                role=role,
                level_num=level_num,
                recipient=notify_email,
                hours_overdue=hours_overdue,
            )
        else:
            # Log-only escalation when no email is configured for this level
            log.info(
                "Escalation level %d (%s) triggered for %s %s — no email configured",
                level_num,
                role,
                entity_type,
                entity.id,
            )
            notified = True  # considered successful (no channel configured)

        # Update entity escalation tracking
        self._update_entity_level(entity, entity_type, level_num, now)

        # Record in audit trail
        audit = AuditTrail(session)
        audit.record(
            action="escalation_triggered",
            entity_type=entity_type,
            entity_id=str(entity.id),
            actor="escalation_engine",
            metadata={
                "policy_name": policy.name,
                "policy_id": str(policy.id),
                "previous_level": previous_level,
                "new_level": level_num,
                "role": role,
                "hours_overdue": round(hours_overdue, 1),
                "notified": notified,
                "notify_email": notify_email or None,
                "error": error or None,
            },
        )

        event = EscalationEvent(
            entity_type=entity_type,
            entity_id=str(entity.id),
            policy_name=policy.name,
            previous_level=previous_level,
            new_level=level_num,
            role=role,
            delay_hours=delay_hours,
            hours_overdue=round(hours_overdue, 1),
            notified=notified,
            error=error,
        )

        log.info(
            "Escalated %s %s: level %d -> %d (%s), %.1fh overdue, policy=%s, notified=%s",
            entity_type,
            entity.id,
            previous_level,
            level_num,
            role,
            hours_overdue,
            policy.name,
            notified,
        )

        return event

    def get_escalation_status(
        self,
        session: Session,
        entity_type: str,
        entity_id: str,
    ) -> EscalationStatus | None:
        """Return the current escalation level and history for an entity.

        Looks up the entity in the database and queries the audit trail
        for past escalation events.

        Args:
            session: Active SQLAlchemy session.
            entity_type: ``"poam"`` or ``"issue"``.
            entity_id: Primary key of the entity.

        Returns:
            EscalationStatus or None if the entity does not exist.
        """
        model_cls = _ESCALATION_ENTITY_MAP.get(entity_type)
        if not model_cls:
            log.warning("Unknown entity type for escalation status: %s", entity_type)
            return None

        entity = session.query(model_cls).filter_by(id=entity_id).first()
        if not entity:
            return None

        current_level = self._get_current_level(entity, entity_type)
        last_escalated = self._get_escalation_sent_at(entity, entity_type)

        # Find the matching policy name (best effort)
        policy_name = self._find_policy_name(session, entity_type, entity)

        # Build history from audit trail
        from warlock.db.models import AuditEntry

        history_entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == entity_type,
                AuditEntry.entity_id == entity_id,
                AuditEntry.action == "escalation_triggered",
            )
            .order_by(AuditEntry.created_at.asc())
            .all()
        )

        history = []
        for entry in history_entries:
            created_at = ensure_aware(entry.created_at)
            history.append(
                {
                    "level": (entry.extra or {}).get("new_level"),
                    "role": (entry.extra or {}).get("role"),
                    "hours_overdue": (entry.extra or {}).get("hours_overdue"),
                    "notified": (entry.extra or {}).get("notified"),
                    "timestamp": created_at.isoformat() if created_at else None,
                }
            )

        return EscalationStatus(
            entity_type=entity_type,
            entity_id=entity_id,
            current_level=current_level,
            last_escalated_at=last_escalated,
            policy_name=policy_name,
            history=history,
        )

    # ------------------------------------------------------------------
    # Internal: scanning helpers
    # ------------------------------------------------------------------

    def _scan_poams(
        self,
        session: Session,
        policies: list[EscalationPolicy],
        now: datetime,
    ) -> list[EscalationEvent]:
        """Scan overdue POAMs and escalate as needed."""
        # Non-terminal statuses for POAMs
        terminal = {"completed", "verified", "closed", "cancelled", "risk_accepted"}

        poams = (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion.isnot(None),
                POAM.status.notin_(terminal),
            )
            .all()
        )

        events: list[EscalationEvent] = []
        for poam in poams:
            due = ensure_aware(poam.scheduled_completion)
            if due is None or due > now:
                continue

            hours_overdue = (now - due).total_seconds() / 3600.0
            severity = (poam.severity or "medium").lower()

            matching_policies = self._match_policies(
                policies,
                "poam",
                severity,
            )
            for policy in matching_policies:
                event = self._try_escalate(
                    session,
                    poam,
                    "poam",
                    policy,
                    hours_overdue,
                )
                if event:
                    events.append(event)

        return events

    def _scan_issues(
        self,
        session: Session,
        policies: list[EscalationPolicy],
        now: datetime,
    ) -> list[EscalationEvent]:
        """Scan overdue Issues and escalate as needed."""
        terminal = {"closed", "risk_accepted", "verified"}

        issues = (
            session.query(Issue)
            .filter(
                Issue.due_date.isnot(None),
                Issue.status.notin_(terminal),
            )
            .all()
        )

        events: list[EscalationEvent] = []
        for issue in issues:
            due = ensure_aware(issue.due_date)
            if due is None or due > now:
                continue

            hours_overdue = (now - due).total_seconds() / 3600.0
            severity = (issue.priority or "medium").lower()

            matching_policies = self._match_policies(
                policies,
                "issue",
                severity,
            )
            for policy in matching_policies:
                event = self._try_escalate(
                    session,
                    issue,
                    "issue",
                    policy,
                    hours_overdue,
                )
                if event:
                    events.append(event)

        return events

    def _match_policies(
        self,
        policies: list[EscalationPolicy],
        entity_type: str,
        severity: str,
    ) -> list[EscalationPolicy]:
        """Return policies that apply to this entity type and severity."""
        matched: list[EscalationPolicy] = []
        for policy in policies:
            # Check entity type scope
            entity_types = policy.entity_types or []
            if entity_types and entity_type not in entity_types:
                continue

            # Check minimum severity
            min_sev = (policy.min_severity or "high").lower()
            if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(min_sev, 0):
                continue

            matched.append(policy)
        return matched

    def _try_escalate(
        self,
        session: Session,
        entity: POAM | Issue,
        entity_type: str,
        policy: EscalationPolicy,
        hours_overdue: float,
    ) -> EscalationEvent | None:
        """Check if the entity should be escalated under this policy.

        Finds the highest applicable level based on hours_overdue and
        the entity's current escalation_level. Respects the cooldown
        period between notifications.
        """
        current_level = self._get_current_level(entity, entity_type)
        last_sent = self._get_escalation_sent_at(entity, entity_type)
        now = datetime.now(timezone.utc)

        # Check cooldown: skip if last escalation was within cooldown window
        cooldown_minutes = policy.cooldown_minutes or 60
        if last_sent is not None:
            last_sent_aware = ensure_aware(last_sent)
            if last_sent_aware:
                elapsed_minutes = (now - last_sent_aware).total_seconds() / 60.0
                if elapsed_minutes < cooldown_minutes:
                    return None

        # Find the highest applicable level
        levels = policy.levels or []
        if not levels:
            return None

        # Sort levels by level number ascending
        sorted_levels = sorted(levels, key=lambda x: x.get("level", 0))

        target_level = None
        for lvl in sorted_levels:
            lvl_num = lvl.get("level", 0)
            delay = lvl.get("delay_hours", 0)
            if hours_overdue >= delay and lvl_num > current_level:
                target_level = lvl

        if target_level is None:
            return None

        return self.escalate(
            session=session,
            entity=entity,
            entity_type=entity_type,
            policy=policy,
            target_level=target_level,
            hours_overdue=hours_overdue,
        )

    # ------------------------------------------------------------------
    # Internal: entity field access
    # ------------------------------------------------------------------

    @staticmethod
    def _get_current_level(entity: POAM | Issue, entity_type: str) -> int:
        """Read escalation_level from the entity, defaulting to 0."""
        if entity_type == "poam":
            return getattr(entity, "escalation_level", None) or 0
        # Issues do not have escalation_level column — use 0
        return 0

    @staticmethod
    def _get_escalation_sent_at(
        entity: POAM | Issue,
        entity_type: str,
    ) -> datetime | None:
        """Read escalation_sent_at from the entity."""
        if entity_type == "poam":
            val = getattr(entity, "escalation_sent_at", None)
            return ensure_aware(val) if val else None
        return None

    @staticmethod
    def _update_entity_level(
        entity: POAM | Issue,
        entity_type: str,
        new_level: int,
        now: datetime,
    ) -> None:
        """Write escalation tracking fields on the entity.

        Only POAMs have dedicated columns; for Issues the escalation
        state is tracked solely through the audit trail.
        """
        if entity_type == "poam":
            entity.escalation_level = new_level  # type: ignore[attr-defined]
            entity.escalation_sent_at = now  # type: ignore[attr-defined]

    def _find_policy_name(
        self,
        session: Session,
        entity_type: str,
        entity: POAM | Issue,
    ) -> str | None:
        """Best-effort lookup of the policy name that applies to this entity."""
        if entity_type == "poam":
            sev = (getattr(entity, "severity", None) or "medium").lower()
        else:
            sev = (getattr(entity, "priority", None) or "medium").lower()

        # Try to find a policy matching this entity type and severity
        policies = session.query(EscalationPolicy).filter(EscalationPolicy.active.is_(True)).all()
        for policy in policies:
            matched = self._match_policies([policy], entity_type, sev)
            if matched:
                return policy.name

        # Fall back to any active policy
        if policies:
            return policies[0].name
        return None

    # ------------------------------------------------------------------
    # Internal: notification
    # ------------------------------------------------------------------

    @staticmethod
    def _send_escalation_email(
        entity: POAM | Issue,
        entity_type: str,
        policy: EscalationPolicy,
        role: str,
        level_num: int,
        recipient: str,
        hours_overdue: float,
    ) -> tuple[bool, str]:
        """Send an escalation notification email via the AlertRouter.

        Uses the SMTP-backed ``send_email`` method from
        :mod:`warlock.export.alerts`.

        Returns:
            Tuple of (success, error_message).
        """
        from warlock.export.alerts import AlertConfig, AlertRouter

        title = _build_escalation_title(entity, entity_type, hours_overdue)
        description = _build_escalation_description(
            entity,
            entity_type,
            policy,
            role,
            level_num,
            hours_overdue,
        )

        config = AlertConfig(
            channel="email",
            url=recipient,  # url field doubles as recipient for email
        )
        router = AlertRouter(configs=[config])

        try:
            success = router.send_escalation_email(
                recipient=recipient,
                subject=title,
                body_html=description,
            )
            return success, "" if success else "SMTP send returned False"
        except Exception as exc:
            log.exception(
                "Failed to send escalation email to %s for %s %s",
                recipient,
                entity_type,
                entity.id,
            )
            return False, str(exc)


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


def _build_escalation_title(
    entity: POAM | Issue,
    entity_type: str,
    hours_overdue: float,
) -> str:
    """Build a human-readable subject line for the escalation email."""
    label = entity_type.upper()
    days = hours_overdue / 24.0
    if days >= 1:
        overdue_str = f"{days:.0f} day(s)"
    else:
        overdue_str = f"{hours_overdue:.0f} hour(s)"

    if entity_type == "poam":
        desc = getattr(entity, "weakness_description", "") or ""
        short = desc[:80] + ("..." if len(desc) > 80 else "")
    else:
        short = getattr(entity, "title", "") or ""
        short = short[:80] + ("..." if len(short) > 80 else "")

    return f"[Warlock Escalation] {label} {entity.id[:8]} overdue by {overdue_str}: {short}"


def _build_escalation_description(
    entity: POAM | Issue,
    entity_type: str,
    policy: EscalationPolicy,
    role: str,
    level_num: int,
    hours_overdue: float,
) -> str:
    """Build an HTML description for the escalation email body."""
    days = hours_overdue / 24.0

    if entity_type == "poam":
        desc = getattr(entity, "weakness_description", "") or "N/A"
        severity = getattr(entity, "severity", "") or "N/A"
        framework = getattr(entity, "framework", "") or "N/A"
        control = getattr(entity, "control_id", "") or "N/A"
    else:
        desc = getattr(entity, "description", "") or getattr(entity, "title", "") or "N/A"
        severity = getattr(entity, "priority", "") or "N/A"
        framework = getattr(entity, "framework", "") or "N/A"
        control = getattr(entity, "control_id", "") or "N/A"

    return f"""<html>
<body style="font-family: sans-serif; color: #333;">
<h2 style="color: #c0392b;">Escalation Notice &mdash; Level {level_num} ({role})</h2>
<p>An item in Warlock GRC has exceeded its deadline and requires attention.</p>
<table style="border-collapse: collapse; width: 100%; max-width: 600px;">
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Entity Type</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{entity_type.upper()}</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">ID</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{entity.id}</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Framework / Control</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{framework} / {control}</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Severity</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{severity}</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Overdue</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{days:.1f} days ({hours_overdue:.0f} hours)</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Escalation Policy</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{policy.name}</td></tr>
  <tr><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Escalation Level</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">{level_num} ({role})</td></tr>
</table>
<h3>Description</h3>
<p>{desc}</p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="font-size: 12px; color: #888;">
  This is an automated escalation from Warlock GRC.
  Policy: {policy.name} | Cooldown: {policy.cooldown_minutes or 60} minutes
</p>
</body>
</html>"""
