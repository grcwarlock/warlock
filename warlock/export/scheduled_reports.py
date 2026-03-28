"""GAP-081: Scheduled report delivery.

Simple scheduler that generates reports and delivers via email/Slack.
Uses SavedQuery records with a frequency field pattern to track schedules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schedule store (uses SavedQuery model with query_type="scheduled_report")
# ---------------------------------------------------------------------------

_QUERY_TYPE = "scheduled_report"

# Frequency → timedelta mapping
_FREQUENCY_INTERVALS: dict[str, timedelta] = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=90),
}


@dataclass
class ReportSchedule:
    """In-memory representation of a scheduled report."""

    id: str
    name: str
    report_type: str
    frequency: str
    delivery_channel: str  # "email" or "slack"
    recipients: list[str] = field(default_factory=list)
    last_run_at: datetime | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


class ReportScheduler:
    """Manages scheduled report generation and delivery."""

    def __init__(self, session: Session):
        self.session = session

    def schedule(
        self,
        report_type: str,
        frequency: str,
        delivery_channel: str,
        recipients: list[str],
        name: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> str:
        """Create a new report schedule.

        Parameters
        ----------
        report_type: Type of report (e.g. "executive", "compliance", "risk").
        frequency: One of "hourly", "daily", "weekly", "monthly", "quarterly".
        delivery_channel: "email" or "slack".
        recipients: List of email addresses or Slack channel IDs.
        name: Optional human-readable name.
        parameters: Optional extra parameters for report generation.

        Returns
        -------
        ID of the created schedule.
        """
        from warlock.db.models import SavedQuery

        if frequency not in _FREQUENCY_INTERVALS:
            raise ValueError(
                f"Invalid frequency '{frequency}'. "
                f"Must be one of: {', '.join(_FREQUENCY_INTERVALS)}"
            )

        if delivery_channel not in ("email", "slack"):
            raise ValueError(
                f"Invalid delivery_channel '{delivery_channel}'. Use 'email' or 'slack'."
            )

        schedule_name = name or f"{report_type} {frequency} report"
        params = {
            "report_type": report_type,
            "frequency": frequency,
            "delivery_channel": delivery_channel,
            "recipients": recipients,
            **(parameters or {}),
        }

        sq = SavedQuery(
            name=schedule_name,
            description=f"Scheduled {report_type} report — {frequency} via {delivery_channel}",
            sql_text="",  # Not a real SQL query; used as schedule metadata
            query_type=_QUERY_TYPE,
            parameters=params,
            shared=True,
            created_by="system",
        )
        self.session.add(sq)
        self.session.flush()

        log.info(
            "Created report schedule %s: %s (%s via %s)",
            sq.id,
            schedule_name,
            frequency,
            delivery_channel,
        )
        return sq.id

    def list_schedules(self) -> list[ReportSchedule]:
        """Return all active report schedules."""
        from warlock.db.models import SavedQuery

        rows = self.session.query(SavedQuery).filter(SavedQuery.query_type == _QUERY_TYPE).all()

        schedules: list[ReportSchedule] = []
        for row in rows:
            params = row.parameters or {}
            schedules.append(
                ReportSchedule(
                    id=row.id,
                    name=row.name,
                    report_type=params.get("report_type", "unknown"),
                    frequency=params.get("frequency", "daily"),
                    delivery_channel=params.get("delivery_channel", "email"),
                    recipients=params.get("recipients", []),
                    last_run_at=ensure_aware(row.last_run_at) if row.last_run_at else None,
                    parameters=params,
                )
            )
        return schedules

    def run_due(self) -> list[dict[str, Any]]:
        """Check which reports are due, generate and deliver them.

        Returns a list of dicts describing what was run.
        """
        now = datetime.now(timezone.utc)
        schedules = self.list_schedules()
        results: list[dict[str, Any]] = []

        for sched in schedules:
            interval = _FREQUENCY_INTERVALS.get(sched.frequency, timedelta(days=1))
            if sched.last_run_at and (now - sched.last_run_at) < interval:
                continue  # Not due yet

            # Generate and deliver
            try:
                report_data = self._generate_report(sched)
                self._deliver(sched, report_data)

                # Update last_run_at
                self._update_last_run(sched.id, now)

                results.append(
                    {
                        "schedule_id": sched.id,
                        "name": sched.name,
                        "report_type": sched.report_type,
                        "delivered_to": sched.recipients,
                        "channel": sched.delivery_channel,
                        "status": "success",
                    }
                )
                log.info("Delivered scheduled report %s (%s)", sched.id, sched.name)
            except Exception as exc:
                results.append(
                    {
                        "schedule_id": sched.id,
                        "name": sched.name,
                        "status": "error",
                        "error": str(exc),
                    }
                )
                log.warning("Failed to deliver scheduled report %s: %s", sched.id, exc)

        return results

    def _generate_report(self, sched: ReportSchedule) -> dict[str, Any]:
        """Generate a report based on schedule type.

        Returns a simple summary dict. In a full implementation this would
        call into warlock.export.reports or warlock.cli.reports_cmd logic.
        """
        from warlock.db.models import ControlResult, Finding

        # Basic compliance summary
        total_findings = self.session.query(Finding).count()
        total_results = self.session.query(ControlResult).count()
        compliant = (
            self.session.query(ControlResult).filter(ControlResult.status == "compliant").count()
        )

        return {
            "report_type": sched.report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": total_findings,
                "total_control_results": total_results,
                "compliant": compliant,
                "compliance_rate": round(compliant / total_results * 100, 1)
                if total_results
                else 0.0,
            },
        }

    def _deliver(self, sched: ReportSchedule, report_data: dict[str, Any]) -> None:
        """Deliver a report via the configured channel."""
        if sched.delivery_channel == "email":
            self._deliver_email(sched, report_data)
        elif sched.delivery_channel == "slack":
            self._deliver_slack(sched, report_data)

    def _deliver_email(self, sched: ReportSchedule, report_data: dict[str, Any]) -> None:
        """Deliver via email using the email notification service."""
        try:
            from warlock.integrations.email_notifications import EmailNotifier

            notifier = EmailNotifier()
            summary = report_data.get("summary", {})
            body = (
                f"Warlock Scheduled Report: {sched.report_type}\n"
                f"{'=' * 50}\n\n"
                f"Total Findings: {summary.get('total_findings', 0)}\n"
                f"Total Control Results: {summary.get('total_control_results', 0)}\n"
                f"Compliant: {summary.get('compliant', 0)}\n"
                f"Compliance Rate: {summary.get('compliance_rate', 0)}%\n\n"
                f"Generated: {report_data.get('generated_at', '')}\n"
            )
            notifier.send(
                to=sched.recipients,
                subject=f"Warlock {sched.report_type.title()} Report",
                body=body,
            )
        except ImportError:
            log.warning("Email notifier not available; skipping email delivery.")
        except Exception as exc:
            log.warning("Email delivery failed: %s", exc)

    def _deliver_slack(self, sched: ReportSchedule, report_data: dict[str, Any]) -> None:
        """Deliver via Slack webhook (placeholder for real integration)."""
        log.info(
            "Slack delivery placeholder: would send %s report to %s",
            sched.report_type,
            sched.recipients,
        )

    def _update_last_run(self, schedule_id: str, run_time: datetime) -> None:
        """Update the last_run_at timestamp on the SavedQuery."""
        from warlock.db.models import SavedQuery

        sq = self.session.get(SavedQuery, schedule_id)
        if sq:
            sq.last_run_at = run_time
            self.session.flush()
