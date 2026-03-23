"""Base classes and protocols for the domain architecture."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid4())


@dataclass
class QueryFilters:
    """Filters for cross-domain queries. None means 'all'."""

    frameworks: list[str] | None = None
    systems: list[str] | None = None
    owner: str | None = None
    mode: str | None = None
    severity_min: str | None = None
    since: datetime | None = None
    limit: int = 50


@dataclass
class RelatedItem:
    """Cross-domain data projection. Returned by get_related_to()."""

    domain: str
    entity_type: str
    entity_id: str
    summary: str
    severity: str | None = None
    status: str | None = None
    url: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class UrgentItem:
    """Item needing attention. Returned by get_urgent_items()."""

    domain: str
    entity_type: str
    entity_id: str
    summary: str
    severity: str
    priority_score: float
    action_hint: str
    sla_deadline: datetime | None = None
    assigned_to: str | None = None
    framework: str | None = None


@dataclass
class DomainEvent:
    """Event emitted by a domain action. Carries cascade context."""

    event_type: str
    domain: str
    entity_type: str
    entity_id: str
    actor: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utcnow)
    correlation_id: str = field(default_factory=_uuid)


@dataclass
class PolicyScope:
    """Scoping for policy applicability. None fields match everything."""

    frameworks: list[str] | None = None
    systems: list[str] | None = None
    severity: list[str] | None = None
    sources: list[str] | None = None
    asset_types: list[str] | None = None
    departments: list[str] | None = None


@runtime_checkable
class DomainService(Protocol):
    """Interface every domain must implement."""

    @property
    def domain_name(self) -> str: ...

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]: ...

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]: ...

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]: ...
