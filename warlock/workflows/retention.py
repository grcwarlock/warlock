"""Framework-specific data retention with legal hold support."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlMapping,
    ControlResult,
    Finding,
    LegalHold,
    RawEvent,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework retention periods (days)
# ---------------------------------------------------------------------------

FRAMEWORK_RETENTION: dict[str, int] = {
    "hipaa": 2190,  # 6 years
    "fedramp": 1095,  # 3 years
    "nist_800_53": 1095,  # 3 years
    "soc2": 365,  # 1 year
    "iso_27001": 1095,  # 3 years
    "iso_27701": 1095,  # 3 years (GDPR alignment)
    "iso_42001": 1095,  # 3 years
    "pci_dss": 365,  # 1 year
}

DEFAULT_RETENTION_DAYS = 1095  # 3 years fallback


# ---------------------------------------------------------------------------
# RetentionManager
# ---------------------------------------------------------------------------


class RetentionManager:
    """Manages data retention policies, purging, and legal holds."""

    def get_retention_days(self, frameworks: list[str]) -> int:
        """Return the longest retention period across applicable frameworks.

        If no matching frameworks are found, returns the default (3 years).
        """
        if not frameworks:
            return DEFAULT_RETENTION_DAYS

        days = [FRAMEWORK_RETENTION.get(fw.lower(), DEFAULT_RETENTION_DAYS) for fw in frameworks]
        return max(days) if days else DEFAULT_RETENTION_DAYS

    def _has_active_hold(
        self,
        session: Session,
        framework: str | None = None,
        record_date: datetime | None = None,
    ) -> bool:
        """Check if any legal hold covers the given scope.

        W-5: Scoped legal holds only block purging of records that match the
        hold's scope. If all scope fields on a hold are null, it is a global
        hold (blocks everything).

        Args:
            session: SQLAlchemy session.
            framework: Framework of the record being considered.
            record_date: Timestamp of the record being considered.

        Returns:
            True if an active hold covers the given scope.
        """
        now = datetime.now(timezone.utc)
        holds = (
            session.query(LegalHold)
            .filter(
                LegalHold.is_active == True,  # noqa: E712
                (LegalHold.end_date.is_(None)) | (LegalHold.end_date > now),
            )
            .all()
        )
        for hold in holds:
            is_global = (
                hold.framework is None
                and hold.system_profile_id is None
                and hold.date_range_start is None
                and hold.date_range_end is None
            )
            if is_global:
                return True

            # Check framework scope
            if hold.framework and framework and hold.framework != framework:
                continue

            # Check date range scope
            if record_date and hold.date_range_start:
                if ensure_aware(record_date) < ensure_aware(hold.date_range_start):
                    continue
            if record_date and hold.date_range_end:
                if ensure_aware(record_date) > ensure_aware(hold.date_range_end):
                    continue

            # Hold matches scope
            return True

        return False

    def _cutoff_date(self, frameworks: list[str] | None = None) -> datetime:
        """Calculate the cutoff date for purging based on framework retention."""
        if frameworks:
            days = self.get_retention_days(frameworks)
        else:
            # Use the shortest retention when no framework specified
            days = (
                min(FRAMEWORK_RETENTION.values()) if FRAMEWORK_RETENTION else DEFAULT_RETENTION_DAYS
            )
        return datetime.now(timezone.utc) - timedelta(days=days)

    def identify_purgeable(
        self,
        session: Session,
        framework: str | None = None,
    ) -> dict[str, int]:
        """Find records past their retention period and not under legal hold.

        Returns ``{raw_events: N, findings: N, control_results: N, total: N}``.
        """
        if self._has_active_hold(session):
            return {"raw_events": 0, "findings": 0, "control_results": 0, "total": 0}

        frameworks = [framework] if framework else list(FRAMEWORK_RETENTION.keys())
        cutoff = ensure_aware(self._cutoff_date(frameworks if framework else None))

        raw_count = (
            session.query(func.count(RawEvent.id)).filter(RawEvent.ingested_at < cutoff).scalar()
            or 0
        )

        findings_count = (
            session.query(func.count(Finding.id)).filter(Finding.ingested_at < cutoff).scalar() or 0
        )

        results_count = (
            session.query(func.count(ControlResult.id))
            .filter(ControlResult.assessed_at < cutoff)
            .scalar()
            or 0
        )

        total = raw_count + findings_count + results_count
        return {
            "raw_events": raw_count,
            "findings": findings_count,
            "control_results": results_count,
            "total": total,
        }

    def purge_expired(
        self,
        session: Session,
        dry_run: bool = True,
        framework: str | None = None,
    ) -> dict[str, Any]:
        """Delete records past retention. dry_run=True just counts, doesn't delete.

        NEVER purges audit_entries (immutable). Respects legal holds.

        Transactional purge order (W-13):
            1. ControlResults (depend on ControlMappings and Findings via FKs)
            2. ControlMappings (depend on Findings via FKs)
            3. Findings (depend on RawEvents via FKs)
            4. RawEvents (leaf records)

        This order respects foreign key constraints. If the transaction is
        interrupted between steps, orphaned child records (e.g. ControlResults
        referencing deleted Findings) may remain. The caller should wrap
        this in a transaction and retry on failure to avoid partial purges.
        """
        if self._has_active_hold(session):
            return {
                "purged": False,
                "reason": "Active legal hold prevents purging",
                "raw_events": 0,
                "findings": 0,
                "control_results": 0,
                "control_mappings": 0,
                "total": 0,
                "dry_run": dry_run,
            }

        frameworks = [framework] if framework else None
        cutoff = ensure_aware(self._cutoff_date(frameworks))

        # Count what would be purged
        raw_count = (
            session.query(func.count(RawEvent.id)).filter(RawEvent.ingested_at < cutoff).scalar()
            or 0
        )
        findings_count = (
            session.query(func.count(Finding.id)).filter(Finding.ingested_at < cutoff).scalar() or 0
        )
        results_count = (
            session.query(func.count(ControlResult.id))
            .filter(ControlResult.assessed_at < cutoff)
            .scalar()
            or 0
        )
        mappings_count = (
            session.query(func.count(ControlMapping.id))
            .filter(ControlMapping.created_at < cutoff)
            .scalar()
            or 0
        )

        total = raw_count + findings_count + results_count + mappings_count

        if dry_run:
            return {
                "purged": False,
                "reason": "Dry run -- no records deleted",
                "raw_events": raw_count,
                "findings": findings_count,
                "control_results": results_count,
                "control_mappings": mappings_count,
                "total": total,
                "dry_run": True,
                "cutoff_date": cutoff.isoformat(),
            }

        # Actually purge (order matters for FK constraints)
        session.query(ControlResult).filter(ControlResult.assessed_at < cutoff).delete(
            synchronize_session=False
        )
        session.query(ControlMapping).filter(ControlMapping.created_at < cutoff).delete(
            synchronize_session=False
        )
        session.query(Finding).filter(Finding.ingested_at < cutoff).delete(
            synchronize_session=False
        )
        session.query(RawEvent).filter(RawEvent.ingested_at < cutoff).delete(
            synchronize_session=False
        )
        session.flush()

        log.info(
            "Purged %d records (raw=%d, findings=%d, results=%d, mappings=%d) before %s",
            total,
            raw_count,
            findings_count,
            results_count,
            mappings_count,
            cutoff.isoformat(),
        )

        return {
            "purged": True,
            "raw_events": raw_count,
            "findings": findings_count,
            "control_results": results_count,
            "control_mappings": mappings_count,
            "total": total,
            "dry_run": False,
            "cutoff_date": cutoff.isoformat(),
        }

    # ------------------------------------------------------------------
    # Legal holds
    # ------------------------------------------------------------------

    def set_legal_hold(
        self,
        session: Session,
        reason: str,
        start_date: datetime | str,
        end_date: datetime | str | None = None,
        actor: str = "",
    ) -> str:
        """Create a legal hold that prevents purging. Returns hold_id."""
        if isinstance(start_date, str):
            start_date = datetime.fromisoformat(start_date)
        if isinstance(end_date, str):
            end_date = datetime.fromisoformat(end_date)

        hold = LegalHold(
            reason=reason,
            start_date=start_date,
            end_date=end_date,
            created_by=actor,
            is_active=True,
        )
        session.add(hold)
        session.flush()

        log.info("Legal hold created: %s by %s -- %s", hold.id, actor, reason)
        return hold.id

    def remove_legal_hold(
        self,
        session: Session,
        hold_id: str,
        actor: str = "",
    ) -> bool:
        """Deactivate a legal hold. Returns True if found and deactivated."""
        hold = session.query(LegalHold).filter(LegalHold.id == hold_id).first()
        if not hold:
            return False

        hold.is_active = False
        session.flush()

        log.info("Legal hold removed: %s by %s", hold_id, actor)
        return True

    def active_holds(self, session: Session) -> list[dict[str, Any]]:
        """Return all currently active legal holds."""
        now = datetime.now(timezone.utc)
        holds = (
            session.query(LegalHold)
            .filter(
                LegalHold.is_active == True,  # noqa: E712
                (LegalHold.end_date.is_(None)) | (LegalHold.end_date > now),
            )
            .order_by(LegalHold.created_at.desc())
            .all()
        )
        return [
            {
                "id": h.id,
                "reason": h.reason,
                "start_date": h.start_date.isoformat() if h.start_date else None,
                "end_date": h.end_date.isoformat() if h.end_date else None,
                "created_by": h.created_by,
                "is_active": h.is_active,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in holds
        ]

    def retention_report(self, session: Session) -> dict[str, Any]:
        """Report: records by age bucket, purgeable count, active holds."""
        now = datetime.now(timezone.utc)

        # Age buckets
        buckets = {
            "0-90d": 0,
            "90-180d": 0,
            "180-365d": 0,
            "1-3y": 0,
            "3-6y": 0,
            "6y+": 0,
        }

        boundaries = [
            ("0-90d", now - timedelta(days=90), now),
            ("90-180d", now - timedelta(days=180), now - timedelta(days=90)),
            ("180-365d", now - timedelta(days=365), now - timedelta(days=180)),
            ("1-3y", now - timedelta(days=1095), now - timedelta(days=365)),
            ("3-6y", now - timedelta(days=2190), now - timedelta(days=1095)),
        ]

        for label, start, end in boundaries:
            count = (
                session.query(func.count(RawEvent.id))
                .filter(RawEvent.ingested_at >= start, RawEvent.ingested_at < end)
                .scalar()
                or 0
            )
            buckets[label] = count

        # 6y+ bucket
        six_years_ago = now - timedelta(days=2190)
        buckets["6y+"] = (
            session.query(func.count(RawEvent.id))
            .filter(RawEvent.ingested_at < six_years_ago)
            .scalar()
            or 0
        )

        total_records = session.query(func.count(RawEvent.id)).scalar() or 0

        purgeable = self.identify_purgeable(session)
        holds = self.active_holds(session)

        return {
            "total_raw_events": total_records,
            "age_buckets": buckets,
            "purgeable": purgeable,
            "active_holds": holds,
            "active_hold_count": len(holds),
            "framework_retention": FRAMEWORK_RETENTION,
        }
