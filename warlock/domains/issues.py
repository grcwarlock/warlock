"""Issues domain service — unified view of POAMs and Issues."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.models import Issue, POAM
from warlock.domains.base import (
    DomainEvent,
    QueryFilters,
    RelatedItem,
    UrgentItem,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

_SEV_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
_PRIO_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25}


class IssuesDomainService:
    @property
    def domain_name(self) -> str:
        return "issues"

    def __init__(self, session: Session):
        self._session = session

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        now = datetime.now(timezone.utc)
        items: list[UrgentItem] = []

        # POAMs
        pq = self._session.query(POAM).filter(POAM.status.in_(["draft", "open", "in_progress"]))
        if filters.frameworks:
            pq = pq.filter(POAM.framework.in_(filters.frameworks))

        for poam in pq.limit(filters.limit).all():
            score = _SEV_SCORE.get(poam.severity, 10)
            overdue_label = ""
            sc = poam.scheduled_completion
            sc = ensure_aware(sc)
            if sc and sc < now:
                days_overdue = (now - sc).days
                score += min(days_overdue * 5, 100)
                overdue_label = f" — overdue {days_overdue}d"

            desc = poam.weakness_description[:60] if poam.weakness_description else "N/A"
            items.append(
                UrgentItem(
                    domain="issues",
                    entity_type="poam",
                    entity_id=f"poam/{poam.id[:8]}",
                    summary=f"POAM {poam.control_id} ({poam.framework}): {desc} [{poam.severity}]{overdue_label}",
                    severity=poam.severity or "medium",
                    priority_score=score,
                    sla_deadline=sc,
                    framework=poam.framework,
                    action_hint=f"warlock remediate {poam.id[:8]}",
                )
            )

        # Issues
        iq = self._session.query(Issue).filter(
            Issue.status.in_(["open", "assigned", "in_progress"])
        )
        if filters.frameworks:
            iq = iq.filter(Issue.framework.in_(filters.frameworks))

        for issue in iq.limit(filters.limit).all():
            score = _PRIO_SCORE.get(issue.priority, 10)
            title = issue.title[:60] if issue.title else "N/A"
            items.append(
                UrgentItem(
                    domain="issues",
                    entity_type="issue",
                    entity_id=f"issue/{issue.id[:8]}",
                    summary=f"Issue {issue.control_id} ({issue.framework}): {title} [{issue.priority}]",
                    severity=issue.priority or "medium",
                    priority_score=score,
                    framework=issue.framework,
                    assigned_to=issue.assigned_to,
                    action_hint=f"warlock remediate {issue.id[:8]}",
                )
            )
        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        if entity_type != "control":
            return []
        items: list[RelatedItem] = []

        for poam in self._session.query(POAM).filter(POAM.control_id == entity_id).all():
            desc = poam.weakness_description[:80] if poam.weakness_description else "N/A"
            items.append(
                RelatedItem(
                    domain="issues",
                    entity_type="poam",
                    entity_id=poam.id[:8],
                    summary=f"POAM: {desc}",
                    severity=poam.severity,
                    status=poam.status,
                )
            )

        for issue in self._session.query(Issue).filter(Issue.control_id == entity_id).all():
            title = issue.title[:80] if issue.title else "N/A"
            items.append(
                RelatedItem(
                    domain="issues",
                    entity_type="issue",
                    entity_id=issue.id[:8],
                    summary=f"Issue: {title}",
                    severity=issue.priority,
                    status=issue.status,
                )
            )
        return items

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        return []
