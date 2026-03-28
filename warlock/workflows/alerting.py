"""Alerting framework — evaluate rules and manage alert lifecycle.

Uses the existing ``Alert`` model from ``warlock.db.models``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.models import Alert, ControlResult, Finding

log = logging.getLogger(__name__)


class AlertEvaluator:
    """Evaluate alert rules against current compliance state.

    Rules are lightweight Python callables today; a future iteration can
    store them in the DB as ``AlertRule`` rows with JSON conditions.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------------
    # Built-in rules
    # ------------------------------------------------------------------

    def evaluate_rules(self) -> list[Alert]:
        """Run all built-in alert rules and return newly created alerts."""
        created: list[Alert] = []
        created.extend(self._check_critical_findings())
        created.extend(self._check_non_compliant_controls())
        return created

    def _check_critical_findings(self) -> list[Alert]:
        """Alert on critical/high findings that have no open alert yet."""
        from sqlalchemy import and_, func

        existing_finding_ids = set(
            row[0]
            for row in self.session.query(Alert.finding_id)
            .filter(
                Alert.status.in_(["open", "acknowledged", "investigating"]),
                Alert.category == "new_finding",
            )
            .all()
            if row[0]
        )

        findings = (
            self.session.query(Finding)
            .filter(
                and_(
                    Finding.severity.in_(["critical", "high"]),
                    ~Finding.id.in_(existing_finding_ids) if existing_finding_ids else func.true(),
                )
            )
            .limit(100)
            .all()
        )

        created: list[Alert] = []
        for finding in findings:
            if finding.id in existing_finding_ids:
                continue
            alert = Alert(
                title=f"New {finding.severity} finding: {(finding.title or '')[:80]}",
                description=finding.description[:500] if finding.description else None,
                severity=finding.severity or "high",
                category="new_finding",
                finding_id=finding.id,
                framework=finding.framework,
                control_id=finding.control_id,
                rule_name="critical_finding_auto",
                status="open",
                triggered_at=datetime.now(timezone.utc),
            )
            self.session.add(alert)
            created.append(alert)
        return created

    def _check_non_compliant_controls(self) -> list[Alert]:
        """Alert when a control drifts to non_compliant."""
        from sqlalchemy import func

        existing_ctrl_ids = set(
            (row[0], row[1])
            for row in self.session.query(Alert.framework, Alert.control_id)
            .filter(
                Alert.status.in_(["open", "acknowledged", "investigating"]),
                Alert.category == "control_drift",
            )
            .all()
            if row[0] and row[1]
        )

        rows = (
            self.session.query(
                ControlResult.framework,
                ControlResult.control_id,
                func.count(ControlResult.id).label("nc_count"),
            )
            .filter(ControlResult.status == "non_compliant")
            .group_by(ControlResult.framework, ControlResult.control_id)
            .having(func.count(ControlResult.id) >= 3)
            .limit(50)
            .all()
        )

        created: list[Alert] = []
        for fw, ctrl, nc_count in rows:
            if (fw, ctrl) in existing_ctrl_ids:
                continue
            alert = Alert(
                title=f"Control drift: {ctrl} ({fw}) — {nc_count} non-compliant",
                severity="high" if nc_count >= 10 else "medium",
                category="control_drift",
                framework=fw,
                control_id=ctrl,
                rule_name="control_drift_auto",
                status="open",
                triggered_at=datetime.now(timezone.utc),
            )
            self.session.add(alert)
            created.append(alert)
        return created

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def get_active_alerts(
        self,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 50,
    ) -> list[Alert]:
        """Return open/acknowledged/investigating alerts."""
        q = self.session.query(Alert).filter(
            Alert.status.in_(["open", "acknowledged", "investigating"])
        )
        if severity:
            q = q.filter(Alert.severity == severity)
        if category:
            q = q.filter(Alert.category == category)
        return q.order_by(Alert.triggered_at.desc()).limit(limit).all()

    def acknowledge(self, alert_id: str, acknowledged_by: str) -> Alert | None:
        """Acknowledge an alert."""
        alert = self.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None
        alert.status = "acknowledged"
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.now(timezone.utc)
        return alert

    def resolve(
        self,
        alert_id: str,
        resolved_by: str,
        notes: str = "",
    ) -> Alert | None:
        """Resolve an alert."""
        alert = self.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None
        alert.status = "resolved"
        alert.resolved_by = resolved_by
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolution_notes = notes
        return alert
