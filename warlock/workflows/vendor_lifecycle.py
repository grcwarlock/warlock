"""GAP-065: Vendor lifecycle monitoring.

Handles reassessment scheduling, offboarding, and sub-processor tracking
for third-party vendor risk management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import Vendor
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class VendorLifecycleManager:
    """Manages vendor reassessment cadence, offboarding, and sub-processor tracking."""

    def schedule_reassessment(
        self,
        session: Session,
        vendor_id: str,
        frequency_days: int,
    ) -> dict[str, Any]:
        """Schedule or update the reassessment cadence for a vendor.

        Sets ``assessment_cadence_days`` and computes the next assessment date
        from ``last_assessment``.  If no prior assessment exists, the next
        assessment is due ``frequency_days`` from now.

        Args:
            session: SQLAlchemy session.
            vendor_id: Vendor UUID.
            frequency_days: Days between reassessments (e.g. 90, 180, 365).

        Returns:
            Dict with vendor_id, frequency_days, next_assessment_due.
        """
        vendor = session.query(Vendor).filter_by(id=vendor_id).first()
        if not vendor:
            raise ValueError(f"Vendor not found: {vendor_id}")

        if frequency_days < 1:
            raise ValueError("frequency_days must be >= 1")

        vendor.assessment_cadence_days = frequency_days

        now = datetime.now(timezone.utc)
        if vendor.last_assessment:
            last = ensure_aware(vendor.last_assessment)
            next_due = last + timedelta(days=frequency_days)
        else:
            next_due = now + timedelta(days=frequency_days)

        # Store next-due in vendor metadata
        meta = dict(vendor.metadata_ or {})
        meta["next_assessment_due"] = next_due.isoformat()
        vendor.metadata_ = meta

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="vendor_reassessment_scheduled",
            entity_type="vendor",
            entity_id=vendor_id,
            actor="system",
            metadata={
                "frequency_days": frequency_days,
                "next_assessment_due": next_due.isoformat(),
            },
        )

        log.info(
            "Vendor %s reassessment scheduled every %d days, next due %s",
            vendor.name,
            frequency_days,
            next_due.date().isoformat(),
        )
        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "frequency_days": frequency_days,
            "next_assessment_due": next_due.isoformat(),
        }

    def get_due_reassessments(
        self,
        session: Session,
    ) -> list[dict[str, Any]]:
        """Return vendors whose reassessment is due (past or today).

        A vendor is due when:
        - ``assessment_cadence_days`` is set, AND
        - ``last_assessment + cadence`` <= now (or last_assessment is NULL).

        Returns:
            List of dicts with vendor_id, name, last_assessment, days_overdue.
        """
        now = datetime.now(timezone.utc)
        vendors = session.query(Vendor).filter(Vendor.assessment_cadence_days.isnot(None)).all()

        due: list[dict[str, Any]] = []
        for v in vendors:
            if v.last_assessment:
                last = ensure_aware(v.last_assessment)
                next_due = last + timedelta(days=v.assessment_cadence_days)
            else:
                # Never assessed — immediately due
                next_due = now

            if next_due <= now:
                days_overdue = (now - next_due).days
                due.append(
                    {
                        "vendor_id": v.id,
                        "vendor_name": v.name,
                        "tier": v.tier,
                        "last_assessment": last.isoformat() if v.last_assessment else None,
                        "days_overdue": days_overdue,
                    }
                )

        return sorted(due, key=lambda d: d["days_overdue"], reverse=True)

    def initiate_offboarding(
        self,
        session: Session,
        vendor_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Begin vendor offboarding by recording the reason and marking inactive.

        Args:
            session: SQLAlchemy session.
            vendor_id: Vendor UUID.
            reason: Business justification for offboarding.

        Returns:
            Dict summarising the offboarding action.
        """
        vendor = session.query(Vendor).filter_by(id=vendor_id).first()
        if not vendor:
            raise ValueError(f"Vendor not found: {vendor_id}")

        now = datetime.now(timezone.utc)
        meta = dict(vendor.metadata_ or {})
        meta["offboarded_at"] = now.isoformat()
        meta["offboard_reason"] = reason
        meta["status"] = "offboarding"
        vendor.metadata_ = meta

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="vendor_offboarding_initiated",
            entity_type="vendor",
            entity_id=vendor_id,
            actor="system",
            metadata={"reason": reason},
        )

        log.info("Vendor %s offboarding initiated: %s", vendor.name, reason)
        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "reason": reason,
            "offboarded_at": now.isoformat(),
        }

    def track_sub_processor(
        self,
        session: Session,
        vendor_id: str,
        sub_processor_name: str,
        data_types: list[str],
    ) -> dict[str, Any]:
        """Record a sub-processor under a vendor for GDPR Article 28 tracking.

        Sub-processor records are stored in the vendor's metadata JSON.

        Args:
            session: SQLAlchemy session.
            vendor_id: Vendor UUID.
            sub_processor_name: Name of the sub-processor entity.
            data_types: Categories of personal data processed.

        Returns:
            Dict with the updated sub-processor list.
        """
        vendor = session.query(Vendor).filter_by(id=vendor_id).first()
        if not vendor:
            raise ValueError(f"Vendor not found: {vendor_id}")

        now = datetime.now(timezone.utc)
        meta = dict(vendor.metadata_ or {})
        sub_processors: list[dict[str, Any]] = list(meta.get("sub_processors", []))

        # Check for duplicate
        existing = [sp for sp in sub_processors if sp["name"] == sub_processor_name]
        if existing:
            existing[0]["data_types"] = data_types
            existing[0]["updated_at"] = now.isoformat()
        else:
            sub_processors.append(
                {
                    "name": sub_processor_name,
                    "data_types": data_types,
                    "added_at": now.isoformat(),
                }
            )

        meta["sub_processors"] = sub_processors
        vendor.metadata_ = meta
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="vendor_sub_processor_tracked",
            entity_type="vendor",
            entity_id=vendor_id,
            actor="system",
            metadata={
                "sub_processor": sub_processor_name,
                "data_types": data_types,
            },
        )

        log.info(
            "Sub-processor '%s' tracked under vendor %s",
            sub_processor_name,
            vendor.name,
        )
        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "sub_processors": sub_processors,
        }
