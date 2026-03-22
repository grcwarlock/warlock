"""Controls domain service — the central compliance hub."""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, POAM
from warlock.domains.base import (
    DomainEvent, QueryFilters, RelatedItem, UrgentItem,
)

log = logging.getLogger(__name__)

_SEV_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}


class ControlsDomainService:
    """Wraps existing compliance data as a domain service."""

    @property
    def domain_name(self) -> str:
        return "controls"

    def __init__(self, session: Session):
        self._session = session

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        q = self._session.query(
            ControlResult.framework, ControlResult.control_id,
            ControlResult.severity,
            func.count(ControlResult.id).label("count"),
        ).filter(
            ControlResult.status == "non_compliant",
        ).group_by(
            ControlResult.framework, ControlResult.control_id, ControlResult.severity,
        )
        if filters.frameworks:
            q = q.filter(ControlResult.framework.in_(filters.frameworks))
        rows = q.limit(filters.limit).all()

        items = []
        for fw, ctrl, sev, count in rows:
            score = _SEV_SCORE.get(sev, 10) + min(count, 100)
            items.append(UrgentItem(
                domain="controls", entity_type="control",
                entity_id=f"{fw}/{ctrl}",
                summary=f"{ctrl} ({fw}): {count} non-compliant results [{sev}]",
                severity=sev or "medium", priority_score=score,
                action_hint=f"warlock control {ctrl} -f {fw}",
                framework=fw,
            ))
        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        if entity_type != "control":
            return []
        control_id = entity_id
        results = self._session.query(ControlResult).filter(
            ControlResult.control_id == control_id
        ).all()
        if not results:
            return []

        by_status: dict[str, int] = defaultdict(int)
        frameworks: set[str] = set()
        for r in results:
            by_status[r.status] += 1
            frameworks.add(r.framework)

        total = sum(by_status.values())
        compliant = by_status.get("compliant", 0)
        non_compliant = by_status.get("non_compliant", 0)

        items: list[RelatedItem] = [
            RelatedItem(
                domain="controls", entity_type="control_status",
                entity_id=control_id,
                summary=f"Compliant: {compliant}, Non-compliant: {non_compliant}, Total: {total}",
                status="non_compliant" if non_compliant > 0 else "compliant",
                metadata={"by_status": dict(by_status), "frameworks": sorted(frameworks)},
            )
        ]

        poams = self._session.query(POAM).filter(POAM.control_id == control_id).all()
        for poam in poams:
            desc = poam.weakness_description[:80] if poam.weakness_description else "N/A"
            items.append(RelatedItem(
                domain="controls", entity_type="poam",
                entity_id=poam.id,
                summary=f"POAM: {desc} [{poam.status}]",
                severity=poam.severity, status=poam.status,
            ))
        return items

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        return []
