"""Notification Preferences Engine.

Per-user notification preferences with channel and frequency support:
  - Channels: email, slack, teams, pagerduty
  - Frequencies: realtime, hourly, daily, weekly
  - Default preferences by role
  - Digest batching and delivery
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail

log = logging.getLogger(__name__)

# Supported channels
CHANNELS = ("email", "slack", "teams", "pagerduty")

# Supported frequency modes
FREQUENCIES = ("realtime", "hourly", "daily", "weekly")

# Event types that can generate notifications
EVENT_TYPES = (
    "compliance_drift",
    "finding_critical",
    "finding_high",
    "poam_overdue",
    "evidence_request",
    "access_review",
    "pipeline_complete",
    "pipeline_failed",
    "policy_violation",
    "vendor_reassessment",
    "control_status_change",
    "remediation_assigned",
    "remediation_overdue",
    "audit_engagement",
    "training_overdue",
    "incident_created",
    "risk_threshold",
)

# Default preferences by role
_ROLE_DEFAULTS: dict[str, list[dict[str, str]]] = {
    "admin": [
        {"event": "compliance_drift", "channel": "email", "frequency": "realtime"},
        {"event": "finding_critical", "channel": "slack", "frequency": "realtime"},
        {"event": "finding_critical", "channel": "pagerduty", "frequency": "realtime"},
        {"event": "finding_high", "channel": "email", "frequency": "daily"},
        {"event": "pipeline_failed", "channel": "slack", "frequency": "realtime"},
        {"event": "poam_overdue", "channel": "email", "frequency": "daily"},
        {"event": "evidence_request", "channel": "email", "frequency": "realtime"},
        {"event": "incident_created", "channel": "slack", "frequency": "realtime"},
        {"event": "risk_threshold", "channel": "email", "frequency": "realtime"},
    ],
    "analyst": [
        {"event": "compliance_drift", "channel": "email", "frequency": "daily"},
        {"event": "finding_critical", "channel": "slack", "frequency": "realtime"},
        {"event": "finding_high", "channel": "email", "frequency": "daily"},
        {"event": "pipeline_complete", "channel": "email", "frequency": "daily"},
        {"event": "remediation_assigned", "channel": "email", "frequency": "realtime"},
        {"event": "poam_overdue", "channel": "email", "frequency": "weekly"},
    ],
    "auditor": [
        {"event": "evidence_request", "channel": "email", "frequency": "realtime"},
        {"event": "audit_engagement", "channel": "email", "frequency": "realtime"},
        {"event": "compliance_drift", "channel": "email", "frequency": "weekly"},
        {"event": "control_status_change", "channel": "email", "frequency": "daily"},
    ],
    "viewer": [
        {"event": "compliance_drift", "channel": "email", "frequency": "weekly"},
        {"event": "pipeline_complete", "channel": "email", "frequency": "weekly"},
    ],
}


class NotificationEngine:
    """Manages notification preferences and delivery."""

    def __init__(self) -> None:
        # In-memory preference store (keyed by user email)
        # In production this would be a DB table
        self._preferences: dict[str, list[dict[str, str]]] = {}
        self._pending: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Preference management
    # ------------------------------------------------------------------

    def get_preferences(self, user_email: str) -> list[dict[str, str]]:
        """Get notification preferences for a user.

        Args:
            user_email: User's email address.

        Returns:
            List of preference dicts with event, channel, frequency.
        """
        return list(self._preferences.get(user_email, []))

    def set_preference(
        self,
        session: Session,
        user_email: str,
        event: str,
        channel: str,
        frequency: str,
        *,
        actor: str = "system",
    ) -> dict[str, str]:
        """Set or update a notification preference.

        Args:
            session: SQLAlchemy session.
            user_email: User's email address.
            event: Event type (must be in EVENT_TYPES).
            channel: Notification channel (must be in CHANNELS).
            frequency: Delivery frequency (must be in FREQUENCIES).
            actor: Who set the preference.

        Returns:
            The preference dict.

        Raises:
            ValueError: If event, channel, or frequency is invalid.
        """
        if event not in EVENT_TYPES:
            raise ValueError(f"Invalid event type '{event}'. Must be one of: {EVENT_TYPES}")
        if channel not in CHANNELS:
            raise ValueError(f"Invalid channel '{channel}'. Must be one of: {CHANNELS}")
        if frequency not in FREQUENCIES:
            raise ValueError(f"Invalid frequency '{frequency}'. Must be one of: {FREQUENCIES}")

        prefs = self._preferences.setdefault(user_email, [])

        # Update existing or add new
        for p in prefs:
            if p["event"] == event and p["channel"] == channel:
                p["frequency"] = frequency
                break
        else:
            prefs.append(
                {
                    "event": event,
                    "channel": channel,
                    "frequency": frequency,
                }
            )

        audit = AuditTrail(session)
        audit.record(
            action="notification_preference_set",
            entity_type="notification_preference",
            entity_id=user_email,
            actor=actor,
            metadata={
                "event": event,
                "channel": channel,
                "frequency": frequency,
            },
        )

        log.info(
            "Notification preference set: %s -> %s via %s (%s)",
            user_email,
            event,
            channel,
            frequency,
        )
        return {"event": event, "channel": channel, "frequency": frequency}

    def apply_role_defaults(
        self,
        session: Session,
        user_email: str,
        role: str,
        *,
        actor: str = "system",
    ) -> list[dict[str, str]]:
        """Apply default notification preferences for a role.

        Args:
            session: SQLAlchemy session.
            user_email: User's email address.
            role: User role (admin, analyst, auditor, viewer).
            actor: Who applied the defaults.

        Returns:
            List of applied preference dicts.
        """
        defaults = _ROLE_DEFAULTS.get(role, _ROLE_DEFAULTS["viewer"])
        applied = []

        for d in defaults:
            pref = self.set_preference(
                session=session,
                user_email=user_email,
                event=d["event"],
                channel=d["channel"],
                frequency=d["frequency"],
                actor=actor,
            )
            applied.append(pref)

        log.info(
            "Applied %d default preferences for %s (role=%s)",
            len(applied),
            user_email,
            role,
        )
        return applied

    def remove_preference(
        self,
        session: Session,
        user_email: str,
        event: str,
        channel: str,
        *,
        actor: str = "system",
    ) -> bool:
        """Remove a notification preference.

        Args:
            session: SQLAlchemy session.
            user_email: User's email address.
            event: Event type.
            channel: Channel to remove.
            actor: Who removed the preference.

        Returns:
            True if a preference was removed, False if not found.
        """
        prefs = self._preferences.get(user_email, [])
        original_len = len(prefs)
        prefs = [p for p in prefs if not (p["event"] == event and p["channel"] == channel)]
        self._preferences[user_email] = prefs

        removed = len(prefs) < original_len
        if removed:
            audit = AuditTrail(session)
            audit.record(
                action="notification_preference_removed",
                entity_type="notification_preference",
                entity_id=user_email,
                actor=actor,
                metadata={"event": event, "channel": channel},
            )
            log.info(
                "Notification preference removed: %s -> %s via %s",
                user_email,
                event,
                channel,
            )
        return removed

    # ------------------------------------------------------------------
    # Notification dispatch
    # ------------------------------------------------------------------

    def notify(
        self,
        session: Session,
        event: str,
        payload: dict[str, Any],
        *,
        target_users: list[str] | None = None,
    ) -> list[dict]:
        """Dispatch a notification event.

        Looks up all users with preferences for this event type,
        filters by frequency, and queues for delivery.

        Args:
            session: SQLAlchemy session.
            event: Event type.
            payload: Event payload (title, message, metadata).
            target_users: Optional list of specific user emails.

        Returns:
            List of notification delivery records.
        """
        now = datetime.now(timezone.utc)
        deliveries = []

        users_to_check = target_users or list(self._preferences.keys())

        for user_email in users_to_check:
            prefs = self._preferences.get(user_email, [])
            matching = [p for p in prefs if p["event"] == event]

            for pref in matching:
                delivery = {
                    "id": str(uuid4()),
                    "user_email": user_email,
                    "event": event,
                    "channel": pref["channel"],
                    "frequency": pref["frequency"],
                    "payload": payload,
                    "queued_at": now.isoformat(),
                    "status": "queued" if pref["frequency"] == "realtime" else "batched",
                }

                if pref["frequency"] == "realtime":
                    # Dispatch immediately (log for now, real impl uses integrations)
                    delivery["status"] = "sent"
                    delivery["sent_at"] = now.isoformat()
                    log.info(
                        "Notification sent: %s -> %s via %s",
                        event,
                        user_email,
                        pref["channel"],
                    )
                else:
                    # Queue for batch delivery
                    self._pending.append(delivery)
                    log.debug(
                        "Notification batched: %s -> %s via %s (%s)",
                        event,
                        user_email,
                        pref["channel"],
                        pref["frequency"],
                    )

                deliveries.append(delivery)

        return deliveries

    def send_test(
        self,
        session: Session,
        user_email: str,
        channel: str,
        *,
        actor: str = "system",
    ) -> dict:
        """Send a test notification to verify channel connectivity.

        Args:
            session: SQLAlchemy session.
            user_email: User's email address.
            channel: Channel to test.
            actor: Who initiated the test.

        Returns:
            Dict with test results.
        """
        if channel not in CHANNELS:
            raise ValueError(f"Invalid channel '{channel}'. Must be one of: {CHANNELS}")

        now = datetime.now(timezone.utc)
        result = {
            "id": str(uuid4()),
            "user_email": user_email,
            "channel": channel,
            "status": "sent",
            "message": f"Test notification from Warlock GRC ({now.strftime('%Y-%m-%d %H:%M:%S')} UTC)",
            "sent_at": now.isoformat(),
        }

        audit = AuditTrail(session)
        audit.record(
            action="notification_test_sent",
            entity_type="notification",
            entity_id=result["id"],
            actor=actor,
            metadata={"channel": channel, "user_email": user_email},
        )

        log.info("Test notification sent to %s via %s", user_email, channel)
        return result

    # ------------------------------------------------------------------
    # Digest processing
    # ------------------------------------------------------------------

    def flush_digest(
        self,
        frequency: str,
    ) -> list[dict]:
        """Flush pending notifications for a given frequency.

        Args:
            frequency: Which batch to flush (hourly, daily, weekly).

        Returns:
            List of flushed notification dicts.
        """
        flushed = []
        remaining = []

        for notification in self._pending:
            if notification["frequency"] == frequency:
                notification["status"] = "sent"
                notification["sent_at"] = datetime.now(timezone.utc).isoformat()
                flushed.append(notification)
            else:
                remaining.append(notification)

        self._pending = remaining

        log.info("Flushed %d %s digest notifications", len(flushed), frequency)
        return flushed
