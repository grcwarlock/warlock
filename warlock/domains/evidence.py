"""Evidence domain service — freshness, sufficiency, and evidence lifecycle."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlMapping, ControlResult
from warlock.domains.base import (
    DomainEvent,
    QueryFilters,
    RelatedItem,
    UrgentItem,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class EvidenceDomainService:
    @property
    def domain_name(self) -> str:
        return "evidence"

    def __init__(self, session: Session, stale_threshold_days: int = 90):
        self._session = session
        self._stale_days = stale_threshold_days

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        """Controls with stale evidence."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._stale_days)

        q = (
            self._session.query(
                ControlResult.framework,
                ControlResult.control_id,
                func.max(ControlResult.assessed_at).label("last_assessed"),
            )
            .group_by(ControlResult.framework, ControlResult.control_id)
            .having(func.max(ControlResult.assessed_at) < cutoff)
        )
        if filters.frameworks:
            q = q.filter(ControlResult.framework.in_(filters.frameworks))

        items = []
        now = datetime.now(timezone.utc)
        for fw, ctrl, last in q.limit(filters.limit).all():
            last = ensure_aware(last)
            days_ago = (now - last).days if last else 999
            items.append(
                UrgentItem(
                    domain="evidence",
                    entity_type="stale_evidence",
                    entity_id=f"{fw}/{ctrl}",
                    summary=f"{ctrl} ({fw}): evidence stale — last assessed {days_ago}d ago (threshold: {self._stale_days}d)",
                    severity="medium",
                    priority_score=30 + min(days_ago - self._stale_days, 50),
                    action_hint=f"warlock evidence refresh --control {ctrl} -f {fw}",
                    framework=fw,
                )
            )
        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        if entity_type != "control":
            return []
        control_id = entity_id

        finding_count = (
            self._session.query(func.count(ControlMapping.id))
            .filter(ControlMapping.control_id == control_id)
            .scalar()
        ) or 0

        latest = (
            self._session.query(func.max(ControlResult.assessed_at))
            .filter(ControlResult.control_id == control_id)
            .scalar()
        )

        if finding_count == 0 and latest is None:
            return []

        now = datetime.now(timezone.utc)
        latest = ensure_aware(latest)
        days_ago = (now - latest).days if latest else None
        stale = days_ago is not None and days_ago > self._stale_days
        freshness = "stale" if stale else "current" if days_ago is not None else "unknown"

        return [
            RelatedItem(
                domain="evidence",
                entity_type="evidence_summary",
                entity_id=control_id,
                summary=f"{finding_count} findings mapped, last assessed {days_ago}d ago, freshness: {freshness}",
                status=freshness,
                metadata={
                    "finding_count": finding_count,
                    "days_since_assessment": days_ago,
                    "stale": stale,
                },
            )
        ]

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        """On new finding, emit an evidence-request event for stale controls."""
        if event.event_type != "finding.created":
            return []

        control_id = event.payload.get("control_id", "")
        framework = event.payload.get("framework", "")
        if not control_id:
            return []

        # Check if the linked control has stale evidence
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._stale_days)
        latest = (
            self._session.query(func.max(ControlResult.assessed_at))
            .filter(
                ControlResult.control_id == control_id,
                ControlResult.framework == framework,
            )
            .scalar()
        )
        if latest is not None:
            latest = ensure_aware(latest)
            if latest >= cutoff:
                return []  # Evidence is fresh — no action needed

        log.info(
            "Evidence request triggered for %s/%s (stale or missing)",
            framework,
            control_id,
        )
        return [
            DomainEvent(
                event_type="evidence.request_created",
                domain="evidence",
                entity_type="control",
                entity_id=control_id,
                actor="system",
                payload={
                    "framework": framework,
                    "reason": "stale_evidence",
                    "finding_id": event.entity_id,
                },
            )
        ]
