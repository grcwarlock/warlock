# Domain Architecture Phase 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the domain service infrastructure (base classes, registry, event bus, policy engine) and three proof-of-concept domain services (Controls, Issues, Evidence) with cross-domain CLI commands (`warlock control`, `warlock briefing`, `warlock policy`).

**Architecture:** Event Mesh + Unified Policy pattern. Each domain implements a `DomainService` protocol. A `DomainRegistry` aggregates all services. CLI commands compose cross-domain views by querying the registry. The `PolicyEngine` stores operational rules that domains consume at decision time. The `DomainEventBus` extends the existing `EventBus` with domain-level events and cascade safety.

**Tech Stack:** Python 3.12+, SQLAlchemy, Click, Rich, Alembic, pytest

**Spec:** `docs/superpowers/specs/2026-03-22-domain-architecture-design.md`

**Key constraints:**
- Additive — do NOT delete or rewrite existing modules. Domain services wrap and delegate to them.
- All 556+ existing tests must continue passing after every task.
- Demo seed must still produce 81 connectors, 5,008 findings, 373,852 mappings.
- Follow existing patterns: CLI commands use `@cli.command()` from `warlock.cli`, DB models extend `Base` from `warlock.db.models`, tests use in-memory SQLite.

---

## CRITICAL ERRATA — Apply These Fixes During Implementation

The code examples below contain column name mismatches vs the actual DB models. The executing agent MUST apply these corrections when implementing tasks 4, 6, 7, 8, and 12:

**E1: POAM model uses `weakness_description`, not `weakness`**
- Everywhere the plan says `weakness="..."` or `poam.weakness`, use `weakness_description` instead.
- POAM uses `scheduled_completion`, not `due_date`. Use `scheduled_completion` everywhere.

**E2: ControlResult requires a full FK chain to test**
- `ControlResult` requires `control_mapping_id` (non-nullable FK) and `finding_id` (non-nullable FK).
- `ControlResult` has NO `detail` or `sha256` columns — remove those from test seed data.
- `ControlResult` uses `assessor` (not a generic field), `assertion_name`, `assertion_passed`.
- To create a ControlResult in tests, you must first create: `ConnectorRun` → `RawEvent` → `Finding` → `ControlMapping` → `ControlResult`.

**E3: RawEvent correct columns**
- `RawEvent` has `raw_data` (not `payload`), `ingested_at` (not `collected_at`), `provider` (required).
- `RawEvent` requires `connector_run_id` (non-nullable FK) — create a `ConnectorRun` first.
- `RawEvent` has no `connector_name` column.

**E4: ControlMapping requires `mapping_method` and `confidence`**
- Both are `nullable=False`. Use `mapping_method="explicit"` and `confidence=1.0`.

**E5: Policy model DateTime columns**
- Use `DateTime(timezone=True)` on all new model columns (Policy, PolicyHistory, Asset, Vendor) to match existing codebase patterns. The plan examples use bare `DateTime` — add `timezone=True`.

**E6: CLI test fixture must reset session factories**
- In the `_use_test_db` fixture, also set `eng._session_factory = None` and `eng._read_session_factory = None` after resetting `eng._engine`.

**E7: Helper function for test seed data**
Create a `_seed_full_chain()` helper in `tests/test_domain_services.py` that builds the complete FK chain (ConnectorRun → RawEvent → Finding → ControlMapping → ControlResult) and reuse it across all domain service tests. This avoids repeating the FK chain setup in every test.

---

## File Structure

```
warlock/domains/               # NEW — all new files
  __init__.py                  # Exports DomainRegistry singleton + init function
  base.py                     # Protocol, dataclasses: DomainService, DomainEvent,
                               # QueryFilters, RelatedItem, UrgentItem, PolicyScope
  bus.py                       # DomainEventBus — extends EventBus with cascade safety
  registry.py                  # DomainRegistry implementation
  policy_engine.py             # PolicyEngine service + Policy resolution logic
  controls.py                  # ControlsDomainService (proof of concept)
  issues.py                    # IssuesDomainService (proof of concept)
  evidence.py                  # EvidenceDomainService (proof of concept)
  briefing.py                  # BriefingDomainService (composes from all domains)

warlock/db/models.py           # MODIFY — add Policy, PolicyHistory, Asset, Vendor models
warlock/db/migrations/versions/
  b3c4d5e6f7a8_add_domain_models.py  # NEW — migration for new tables

warlock/cli/__init__.py        # MODIFY — register new CLI modules
warlock/cli/policy_cmd.py      # NEW — warlock policy set/list/show/history
warlock/cli/control_cmd.py     # NEW — warlock control <id> (cross-domain hub)
warlock/cli/briefing_cmd.py    # NEW — warlock briefing
warlock/cli/issue_cmd.py       # NEW — warlock issue (unified POAMs + Issues view)

tests/test_domains.py          # NEW — domain base classes, registry, event bus
tests/test_policy_engine.py    # NEW — policy CRUD, resolution, scoping
tests/test_domain_services.py  # NEW — controls, issues, evidence services
tests/test_domain_cli.py       # NEW — CLI integration tests
```

---

### Task 1: Domain Base Classes and Protocols

**Files:**
- Create: `warlock/domains/__init__.py`
- Create: `warlock/domains/base.py`
- Test: `tests/test_domains.py`

- [ ] **Step 1: Write failing tests for base dataclasses**

```python
# tests/test_domains.py
"""Tests for domain infrastructure: base classes, registry, event bus."""

from datetime import datetime, timezone

import pytest


class TestDomainDataclasses:
    """Verify base dataclasses can be created and have correct defaults."""

    def test_query_filters_defaults(self):
        from warlock.domains.base import QueryFilters

        f = QueryFilters()
        assert f.frameworks is None
        assert f.owner is None
        assert f.mode is None
        assert f.limit == 50

    def test_query_filters_with_values(self):
        from warlock.domains.base import QueryFilters

        f = QueryFilters(frameworks=["soc2"], owner="eve@acme.com", mode="audit-prep")
        assert f.frameworks == ["soc2"]
        assert f.owner == "eve@acme.com"
        assert f.mode == "audit-prep"

    def test_related_item_creation(self):
        from warlock.domains.base import RelatedItem

        item = RelatedItem(
            domain="risk",
            entity_type="risk_score",
            entity_id="rs-123",
            summary="ALE $3.5M for AC-2",
            severity="high",
        )
        assert item.domain == "risk"
        assert item.severity == "high"
        assert item.metadata is None

    def test_urgent_item_creation(self):
        from warlock.domains.base import UrgentItem

        item = UrgentItem(
            domain="issues",
            entity_type="poam",
            entity_id="POAM-123",
            summary="Root access keys active",
            severity="critical",
            priority_score=95.0,
            action_hint="warlock issue transition POAM-123 --to in_progress",
        )
        assert item.priority_score == 95.0
        assert item.action_hint.startswith("warlock")

    def test_domain_event_creation(self):
        from warlock.domains.base import DomainEvent

        evt = DomainEvent(
            event_type="issue.completed",
            domain="issues",
            entity_type="issue",
            entity_id="ISS-456",
            actor="eve@acme.com",
            payload={"control": "AC-2"},
        )
        assert evt.event_type == "issue.completed"
        assert evt.correlation_id  # auto-generated
        assert evt.timestamp  # auto-generated

    def test_policy_scope_matches_all_when_empty(self):
        from warlock.domains.base import PolicyScope

        scope = PolicyScope()
        assert scope.frameworks is None  # None means "all"
        assert scope.severity is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domains.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'warlock.domains'`

- [ ] **Step 3: Implement base dataclasses**

```python
# warlock/domains/__init__.py
"""Domain architecture — cross-domain services, event bus, and policy engine."""

# warlock/domains/base.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domains.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Run full test suite to verify nothing broke**

Run: `pytest --tb=short -q`
Expected: 556+ tests pass, 0 failures

- [ ] **Step 6: Commit**

```bash
git add warlock/domains/__init__.py warlock/domains/base.py tests/test_domains.py
git commit -m "feat(domains): add base dataclasses and DomainService protocol"
```

---

### Task 2: DomainRegistry

**Files:**
- Create: `warlock/domains/registry.py`
- Test: `tests/test_domains.py` (append)

- [ ] **Step 1: Write failing tests for DomainRegistry**

Append to `tests/test_domains.py`:

```python
class FakeService:
    """Minimal DomainService for testing."""

    def __init__(self, name: str, urgent: list | None = None, related: list | None = None):
        self._name = name
        self._urgent = urgent or []
        self._related = related or []

    @property
    def domain_name(self) -> str:
        return self._name

    def get_urgent_items(self, filters):
        return self._urgent

    def get_related_to(self, entity_type: str, entity_id: str):
        return self._related

    def handle_event(self, event):
        return []


class TestDomainRegistry:
    def test_register_and_get(self):
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        svc = FakeService("risk")
        reg.register(svc)
        assert reg.get("risk") is svc

    def test_get_unknown_returns_none(self):
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        assert reg.get("nonexistent") is None

    def test_all_services(self):
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        reg.register(FakeService("a"))
        reg.register(FakeService("b"))
        assert len(reg.all_services()) == 2

    def test_get_related_to_aggregates(self):
        from warlock.domains.base import RelatedItem
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        reg.register(FakeService("risk", related=[
            RelatedItem(domain="risk", entity_type="score", entity_id="1", summary="$3.5M ALE")
        ]))
        reg.register(FakeService("evidence", related=[
            RelatedItem(domain="evidence", entity_type="status", entity_id="2", summary="stale")
        ]))
        reg.register(FakeService("empty"))  # returns nothing

        result = reg.get_related_to("control", "AC-2")
        assert "risk" in result
        assert "evidence" in result
        assert "empty" not in result
        assert len(result) == 2

    def test_get_briefing_sorts_by_priority(self):
        from warlock.domains.base import UrgentItem
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        reg.register(FakeService("a", urgent=[
            UrgentItem(domain="a", entity_type="x", entity_id="1",
                       summary="low", severity="low", priority_score=10.0,
                       action_hint="fix it")
        ]))
        reg.register(FakeService("b", urgent=[
            UrgentItem(domain="b", entity_type="x", entity_id="2",
                       summary="high", severity="critical", priority_score=95.0,
                       action_hint="fix it now")
        ]))

        items = reg.get_briefing()
        assert items[0].priority_score == 95.0
        assert items[1].priority_score == 10.0

    def test_get_briefing_with_filters(self):
        from warlock.domains.base import QueryFilters, UrgentItem
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        reg.register(FakeService("a", urgent=[
            UrgentItem(domain="a", entity_type="x", entity_id="1",
                       summary="item", severity="high", priority_score=50.0,
                       action_hint="fix", framework="soc2")
        ]))

        filters = QueryFilters(frameworks=["soc2"])
        items = reg.get_briefing(filters)
        assert len(items) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domains.py::TestDomainRegistry -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'warlock.domains.registry'`

- [ ] **Step 3: Implement DomainRegistry**

```python
# warlock/domains/registry.py
"""Central registry of all domain services."""

from __future__ import annotations

from warlock.domains.base import DomainService, QueryFilters, RelatedItem, UrgentItem


class DomainRegistry:
    """Aggregates domain services for cross-domain queries."""

    def __init__(self) -> None:
        self._services: dict[str, DomainService] = {}

    def register(self, service: DomainService) -> None:
        self._services[service.domain_name] = service

    def get(self, domain_name: str) -> DomainService | None:
        return self._services.get(domain_name)

    def all_services(self) -> list[DomainService]:
        return list(self._services.values())

    def get_related_to(
        self, entity_type: str, entity_id: str
    ) -> dict[str, list[RelatedItem]]:
        """Query ALL domains for what they know about this entity."""
        result: dict[str, list[RelatedItem]] = {}
        for svc in self._services.values():
            related = svc.get_related_to(entity_type, entity_id)
            if related:
                result[svc.domain_name] = related
        return result

    def get_briefing(
        self, filters: QueryFilters | None = None
    ) -> list[UrgentItem]:
        """Gather urgent items from all domains, sort by priority descending."""
        filters = filters or QueryFilters()
        items: list[UrgentItem] = []
        for svc in self._services.values():
            items.extend(svc.get_urgent_items(filters))
        return sorted(items, key=lambda i: i.priority_score, reverse=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domains.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/domains/registry.py tests/test_domains.py
git commit -m "feat(domains): add DomainRegistry for cross-domain queries"
```

---

### Task 3: DomainEventBus with Cascade Safety

**Files:**
- Create: `warlock/domains/bus.py`
- Test: `tests/test_domains.py` (append)

- [ ] **Step 1: Write failing tests for DomainEventBus**

Append to `tests/test_domains.py`:

```python
class TestDomainEventBus:
    def test_publish_and_subscribe(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        received = []
        bus = DomainEventBus()
        bus.subscribe("issue.completed", lambda e: received.append(e))
        evt = DomainEvent(
            event_type="issue.completed", domain="issues",
            entity_type="issue", entity_id="1", actor="test",
        )
        bus.publish(evt)
        assert len(received) == 1
        assert received[0].entity_id == "1"

    def test_handler_returns_cascade_events(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        cascade_log = []

        def handler(event):
            cascade_log.append(event.event_type)
            if event.event_type == "issue.completed":
                return [DomainEvent(
                    event_type="control.reassessed", domain="assessment",
                    entity_type="control", entity_id="AC-2", actor="system",
                    correlation_id=event.correlation_id,
                )]
            return []

        bus = DomainEventBus()
        bus.subscribe("issue.completed", handler)
        bus.subscribe("control.reassessed", lambda e: cascade_log.append(e.event_type))

        evt = DomainEvent(
            event_type="issue.completed", domain="issues",
            entity_type="issue", entity_id="1", actor="test",
        )
        bus.publish(evt)
        assert "issue.completed" in cascade_log
        assert "control.reassessed" in cascade_log

    def test_cascade_max_depth_prevents_infinite_loop(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        call_count = 0

        def looping_handler(event):
            nonlocal call_count
            call_count += 1
            # Always returns a new event — would loop forever without depth limit
            return [DomainEvent(
                event_type="loop.event", domain="test",
                entity_type="x", entity_id="1", actor="test",
                correlation_id=event.correlation_id,
            )]

        bus = DomainEventBus(max_cascade_depth=5)
        bus.subscribe("loop.event", looping_handler)
        bus.publish(DomainEvent(
            event_type="loop.event", domain="test",
            entity_type="x", entity_id="1", actor="test",
        ))
        assert call_count == 5  # stopped at max depth

    def test_cascade_deduplication(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        call_count = 0

        def counting_handler(event):
            nonlocal call_count
            call_count += 1
            return []

        bus = DomainEventBus()
        bus.subscribe("test.event", counting_handler)

        corr_id = "same-correlation"
        evt1 = DomainEvent(
            event_type="test.event", domain="a",
            entity_type="x", entity_id="1", actor="test",
            correlation_id=corr_id,
        )
        evt2 = DomainEvent(
            event_type="test.event", domain="b",
            entity_type="x", entity_id="1", actor="test",
            correlation_id=corr_id,
        )
        bus.publish(evt1)
        bus.publish_cascade(evt2, corr_id, depth=1)
        # Second publish with same event_type+entity_id+correlation should be deduped
        assert call_count == 1

    def test_wildcard_subscription(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        received = []
        bus = DomainEventBus()
        bus.subscribe_all(lambda e: received.append(e.event_type))
        bus.publish(DomainEvent(
            event_type="a.happened", domain="a",
            entity_type="x", entity_id="1", actor="test",
        ))
        bus.publish(DomainEvent(
            event_type="b.happened", domain="b",
            entity_type="x", entity_id="2", actor="test",
        ))
        assert len(received) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domains.py::TestDomainEventBus -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement DomainEventBus**

```python
# warlock/domains/bus.py
"""Domain event bus with cascade safety."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

from warlock.domains.base import DomainEvent

log = logging.getLogger(__name__)

DomainHandler = Callable[[DomainEvent], list[DomainEvent] | None]


class DomainEventBus:
    """Pub/sub for domain events with cascade support.

    Handlers may return new DomainEvents to trigger cascades.
    Cascade safety: max depth, deduplication within a correlation.
    """

    def __init__(self, max_cascade_depth: int = 5) -> None:
        self._handlers: dict[str, list[DomainHandler]] = defaultdict(list)
        self._wildcard_handlers: list[DomainHandler] = []
        self._max_depth = max_cascade_depth
        # Dedup: set of (correlation_id, event_type, entity_id) seen
        self._seen: set[tuple[str, str, str]] = set()

    def subscribe(self, event_type: str, handler: DomainHandler) -> None:
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: DomainHandler) -> None:
        self._wildcard_handlers.append(handler)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event. Starts a new cascade context."""
        self._seen.clear()
        self._dispatch(event, depth=0)

    def publish_cascade(
        self, event: DomainEvent, correlation_id: str, depth: int
    ) -> None:
        """Publish a cascade event (called internally or for testing)."""
        event.correlation_id = correlation_id
        self._dispatch(event, depth=depth)

    def _dispatch(self, event: DomainEvent, depth: int) -> None:
        if depth >= self._max_depth:
            log.warning(
                "Cascade depth %d reached for %s (correlation=%s). Stopping.",
                depth, event.event_type, event.correlation_id,
            )
            return

        dedup_key = (event.correlation_id, event.event_type, event.entity_id)
        if dedup_key in self._seen:
            log.debug("Dedup: skipping %s/%s in correlation %s",
                      event.event_type, event.entity_id, event.correlation_id)
            return
        self._seen.add(dedup_key)

        cascade_events: list[DomainEvent] = []

        for handler in self._wildcard_handlers:
            cascade_events.extend(self._safe_call(handler, event))

        for handler in self._handlers.get(event.event_type, []):
            cascade_events.extend(self._safe_call(handler, event))

        for cascade_event in cascade_events:
            cascade_event.correlation_id = event.correlation_id
            self._dispatch(cascade_event, depth + 1)

    def _safe_call(
        self, handler: DomainHandler, event: DomainEvent
    ) -> list[DomainEvent]:
        try:
            result = handler(event)
            return result if result else []
        except Exception:
            log.exception(
                "Domain handler failed for event %s", event.event_type
            )
            return []

    def clear(self) -> None:
        self._handlers.clear()
        self._wildcard_handlers.clear()
        self._seen.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domains.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ pass, 0 fail

- [ ] **Step 6: Commit**

```bash
git add warlock/domains/bus.py tests/test_domains.py
git commit -m "feat(domains): add DomainEventBus with cascade safety and dedup"
```

---

### Task 4: Database Models — Policy, PolicyHistory, Asset, Vendor

**Files:**
- Modify: `warlock/db/models.py` (append new models at end)
- Create: `warlock/db/migrations/versions/b3c4d5e6f7a8_add_domain_models.py`
- Test: `tests/test_policy_engine.py`

- [ ] **Step 1: Write failing tests for new models**

```python
# tests/test_policy_engine.py
"""Tests for policy engine: models, CRUD, resolution."""

from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import Base

import pytest


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestPolicyModel:
    def test_create_policy(self, db_session):
        from warlock.db.models import Policy

        p = Policy(
            policy_type="sla",
            scope={"severity": ["critical"]},
            rules={"remediation_days": 14, "escalate_after": 7},
            created_by="admin@acme.com",
            description="Critical SLA",
        )
        db_session.add(p)
        db_session.commit()

        result = db_session.query(Policy).first()
        assert result.policy_type == "sla"
        assert result.rules["remediation_days"] == 14
        assert result.enabled is True
        assert result.priority == 0

    def test_create_policy_history(self, db_session):
        from warlock.db.models import Policy, PolicyHistory

        p = Policy(
            policy_type="retention",
            scope={},
            rules={"days": 365},
            created_by="admin@acme.com",
        )
        db_session.add(p)
        db_session.commit()

        h = PolicyHistory(
            policy_id=p.id,
            action="created",
            new_rules={"days": 365},
            actor="admin@acme.com",
        )
        db_session.add(h)
        db_session.commit()

        result = db_session.query(PolicyHistory).first()
        assert result.action == "created"
        assert result.policy_id == p.id


class TestAssetModel:
    def test_create_asset(self, db_session):
        from warlock.db.models import Asset

        a = Asset(
            resource_id="prod-db-01",
            resource_type="database",
            resource_name="Production PostgreSQL",
            classification="critical",
            criticality=9,
        )
        db_session.add(a)
        db_session.commit()

        result = db_session.query(Asset).first()
        assert result.resource_id == "prod-db-01"
        assert result.classification == "critical"
        assert result.status == "active"


class TestVendorModel:
    def test_create_vendor(self, db_session):
        from warlock.db.models import Vendor

        v = Vendor(
            name="Cloudflare",
            tier="critical",
            risk_score=82.0,
        )
        db_session.add(v)
        db_session.commit()

        result = db_session.query(Vendor).first()
        assert result.name == "Cloudflare"
        assert result.tier == "critical"
        assert result.risk_score == 82.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_policy_engine.py -v`
Expected: FAIL — `ImportError: cannot import name 'Policy' from 'warlock.db.models'`

- [ ] **Step 3: Add new models to `warlock/db/models.py`**

Append at the end of `warlock/db/models.py` (after the last existing model class):

```python
# ---------------------------------------------------------------------------
# Domain Architecture: Policy, Asset, Vendor models
# ---------------------------------------------------------------------------


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_type = Column(String(50), nullable=False, index=True)
    scope = Column(JSONType, nullable=False, default=dict)
    rules = Column(JSONType, nullable=False)
    priority = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)
    created_by = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    effective_at = Column(DateTime, default=_utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    description = Column(Text, default="")

    __table_args__ = (
        Index("ix_policies_type_enabled", "policy_type", "enabled"),
    )


class PolicyHistory(Base):
    __tablename__ = "policy_history"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(
        String(36), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action = Column(String(20), nullable=False)  # created, updated, disabled, deleted
    old_rules = Column(JSONType, nullable=True)
    new_rules = Column(JSONType, nullable=False)
    actor = Column(String(200), nullable=False)
    timestamp = Column(DateTime, default=_utcnow, nullable=False)

    policy = relationship("Policy", backref="history")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    resource_id = Column(String(500), nullable=False, unique=True, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_name = Column(String(500), nullable=True)
    system_id = Column(
        String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"), nullable=True
    )
    owner = Column(String(200), nullable=True)
    classification = Column(String(20), nullable=True)  # critical, high, medium, low
    criticality = Column(Integer, nullable=True)  # 1-10
    status = Column(String(20), default="active")
    first_seen = Column(DateTime, default=_utcnow, nullable=False)
    last_seen = Column(DateTime, default=_utcnow, nullable=False)
    metadata_ = Column("metadata", JSONType, default=dict)

    system = relationship("SystemProfile", backref="assets")


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), nullable=False, unique=True, index=True)
    tier = Column(String(20), nullable=True)  # critical, high, medium, low
    risk_score = Column(Float, nullable=True)
    contract_expires = Column(DateTime, nullable=True)
    last_assessment = Column(DateTime, nullable=True)
    assessment_cadence_days = Column(Integer, nullable=True)
    metadata_ = Column("metadata", JSONType, default=dict)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_policy_engine.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ pass, 0 fail

- [ ] **Step 6: Create Alembic migration**

Run: `cd /Users/jsn/Coding/GitHub/warlock && .venv/bin/alembic revision --autogenerate -m "Add Policy, PolicyHistory, Asset, Vendor tables for domain architecture"`

Then verify the generated migration looks correct (has 4 create_table statements).

- [ ] **Step 7: Commit**

```bash
git add warlock/db/models.py warlock/db/migrations/versions/ tests/test_policy_engine.py
git commit -m "feat(domains): add Policy, Asset, Vendor DB models and migration"
```

---

### Task 5: PolicyEngine Service

**Files:**
- Create: `warlock/domains/policy_engine.py`
- Test: `tests/test_policy_engine.py` (append)

- [ ] **Step 1: Write failing tests for PolicyEngine**

Append to `tests/test_policy_engine.py`:

```python
class TestPolicyEngine:
    def test_set_and_get_policy(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="sla",
            scope={"severity": ["critical"]},
            rules={"remediation_days": 14},
            actor="admin@acme.com",
        )

        result = engine.get("sla", severity="critical")
        assert result is not None
        assert result.rules["remediation_days"] == 14

    def test_get_returns_none_when_no_match(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)
        result = engine.get("sla", severity="critical")
        assert result is None

    def test_specific_scope_beats_global(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)

        # Global policy: 30 days
        engine.set_policy(
            policy_type="sla",
            scope={},
            rules={"remediation_days": 30},
            actor="admin@acme.com",
        )
        # Specific policy: 14 days for critical
        engine.set_policy(
            policy_type="sla",
            scope={"severity": ["critical"]},
            rules={"remediation_days": 14},
            actor="admin@acme.com",
        )

        result = engine.get("sla", severity="critical")
        assert result.rules["remediation_days"] == 14

        # Non-critical falls back to global
        result = engine.get("sla", severity="low")
        assert result.rules["remediation_days"] == 30

    def test_higher_priority_wins(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)

        engine.set_policy(
            policy_type="retention",
            scope={"frameworks": ["pci_dss"]},
            rules={"days": 365},
            actor="admin@acme.com",
            priority=0,
        )
        engine.set_policy(
            policy_type="retention",
            scope={"frameworks": ["pci_dss"]},
            rules={"days": 2555},
            actor="compliance@acme.com",
            priority=10,
        )

        result = engine.get("retention", framework="pci_dss")
        assert result.rules["days"] == 2555

    def test_disabled_policies_excluded(self, db_session):
        from warlock.db.models import Policy
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="sla",
            scope={},
            rules={"remediation_days": 14},
            actor="admin@acme.com",
        )

        # Disable it
        p = db_session.query(Policy).first()
        p.enabled = False
        db_session.commit()

        result = engine.get("sla")
        assert result is None

    def test_set_policy_creates_history(self, db_session):
        from warlock.db.models import PolicyHistory
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="retention",
            scope={},
            rules={"days": 365},
            actor="admin@acme.com",
        )

        history = db_session.query(PolicyHistory).all()
        assert len(history) == 1
        assert history[0].action == "created"
        assert history[0].actor == "admin@acme.com"

    def test_list_policies(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine

        engine = PolicyEngine(db_session)
        engine.set_policy("sla", {}, {"days": 14}, "admin@acme.com")
        engine.set_policy("retention", {}, {"days": 365}, "admin@acme.com")

        all_policies = engine.list_policies()
        assert len(all_policies) == 2

        sla_only = engine.list_policies(policy_type="sla")
        assert len(sla_only) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_policy_engine.py::TestPolicyEngine -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement PolicyEngine**

```python
# warlock/domains/policy_engine.py
"""Unified policy engine — stores and resolves operational rules."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.models import Policy, PolicyHistory

log = logging.getLogger(__name__)


class ResolvedPolicy:
    """A policy resolved for a specific context."""

    def __init__(self, policy: Policy):
        self.id = policy.id
        self.policy_type = policy.policy_type
        self.scope = policy.scope or {}
        self.rules = policy.rules
        self.priority = policy.priority
        self.description = policy.description
        self.created_by = policy.created_by


class PolicyEngine:
    """Central policy store. Domains read policies at decision time."""

    def __init__(self, session: Session):
        self._session = session

    def set_policy(
        self,
        policy_type: str,
        scope: dict,
        rules: dict,
        actor: str,
        priority: int = 0,
        description: str = "",
        effective_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> Policy:
        """Create a new policy and record history."""
        now = datetime.now(timezone.utc)
        policy = Policy(
            policy_type=policy_type,
            scope=scope,
            rules=rules,
            priority=priority,
            created_by=actor,
            created_at=now,
            effective_at=effective_at or now,
            expires_at=expires_at,
            description=description,
        )
        self._session.add(policy)

        history = PolicyHistory(
            policy_id=policy.id,
            action="created",
            new_rules=rules,
            actor=actor,
            timestamp=now,
        )
        self._session.add(history)
        self._session.commit()
        return policy

    def get(self, policy_type: str, **context) -> ResolvedPolicy | None:
        """Get the effective policy for this context.

        Resolution order:
        1. Most specific scope wins
        2. Higher priority wins
        3. Most recently created wins
        """
        now = datetime.now(timezone.utc)
        candidates = (
            self._session.query(Policy)
            .filter(
                Policy.policy_type == policy_type,
                Policy.enabled.is_(True),
                Policy.effective_at <= now,
            )
            .all()
        )

        # Filter out expired
        candidates = [
            p for p in candidates
            if p.expires_at is None or p.expires_at > now
        ]

        if not candidates:
            return None

        # Score each candidate by how well its scope matches the context
        scored: list[tuple[int, int, datetime, Policy]] = []
        for p in candidates:
            specificity = self._scope_match(p.scope or {}, context)
            if specificity >= 0:  # -1 means doesn't match
                scored.append((specificity, p.priority, p.created_at, p))

        if not scored:
            return None

        # Sort: highest specificity, then highest priority, then newest
        scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
        return ResolvedPolicy(scored[0][3])

    def _scope_match(self, scope: dict, context: dict) -> int:
        """Score how well a scope matches a context.

        Returns -1 if scope doesn't match (scope requires something context lacks).
        Returns 0+ for match, higher = more specific.
        """
        if not scope:
            return 0  # Global policy — matches everything, least specific

        specificity = 0
        for key, scope_values in scope.items():
            if not scope_values:
                continue

            # Map context keys to scope keys
            # context: severity="critical" → scope: severity=["critical"]
            # context: framework="soc2" → scope: frameworks=["soc2"]
            context_key = key.rstrip("s") if key.endswith("s") else key
            context_value = context.get(context_key) or context.get(key)

            if context_value is None:
                # Context doesn't specify this dimension — scope still matches
                # but doesn't add specificity
                continue

            if isinstance(scope_values, list):
                if context_value in scope_values:
                    specificity += 1
                else:
                    return -1  # Scope requires a value that doesn't match
            elif scope_values == context_value:
                specificity += 1
            else:
                return -1

        return specificity

    def list_policies(
        self, policy_type: str | None = None, framework: str | None = None
    ) -> list[Policy]:
        """List active policies, optionally filtered."""
        q = self._session.query(Policy).filter(Policy.enabled.is_(True))
        if policy_type:
            q = q.filter(Policy.policy_type == policy_type)
        policies = q.order_by(Policy.policy_type, Policy.priority.desc()).all()

        if framework:
            policies = [
                p for p in policies
                if not p.scope or not p.scope.get("frameworks")
                or framework in p.scope["frameworks"]
            ]

        return policies
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_policy_engine.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ pass, 0 fail

- [ ] **Step 6: Commit**

```bash
git add warlock/domains/policy_engine.py tests/test_policy_engine.py
git commit -m "feat(domains): add PolicyEngine with scope resolution and history"
```

---

### Task 6: Controls Domain Service (Proof of Concept)

**Files:**
- Create: `warlock/domains/controls.py`
- Test: `tests/test_domain_services.py`

This is the first real domain service — it wraps existing compliance data and provides cross-domain views.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_domain_services.py
"""Tests for domain services: controls, issues, evidence."""

from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base, ControlResult, Finding, POAM, Issue, RawEvent, ControlMapping,
)
from warlock.domains.base import QueryFilters

import pytest


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _seed_control_data(session):
    """Seed minimal data for control service tests."""
    now = datetime.now(timezone.utc)

    # A non-compliant control result
    cr = ControlResult(
        framework="soc2", control_id="CC6.1",
        status="non_compliant", severity="high",
        assessor="assertion:mfa_enabled",
        finding_id="f-1",
        assessed_at=now,
        detail={"reason": "MFA not enforced"},
        sha256="abc123",
    )
    session.add(cr)

    # A compliant control result
    cr2 = ControlResult(
        framework="soc2", control_id="CC9.2",
        status="compliant", severity="medium",
        assessor="assertion:third_party_sla",
        finding_id="f-2",
        assessed_at=now,
        detail={},
        sha256="def456",
    )
    session.add(cr2)

    # A POAM for the failing control
    poam = POAM(
        framework="soc2", control_id="CC6.1",
        severity="high", status="open",
        weakness="MFA not enforced for privileged users",
        created_by="admin@acme.com",
    )
    session.add(poam)

    session.commit()
    return {"cr": cr, "cr2": cr2, "poam": poam}


class TestControlsDomainService:
    def test_domain_name(self):
        from warlock.domains.controls import ControlsDomainService

        svc = ControlsDomainService.__new__(ControlsDomainService)
        assert svc.domain_name == "controls"

    def test_get_related_to_control(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_control_data(db_session)
        svc = ControlsDomainService(db_session)

        related = svc.get_related_to("control", "CC6.1")
        assert len(related) > 0
        # Should include status summary and POAM info
        types = [r.entity_type for r in related]
        assert "control_status" in types

    def test_get_urgent_items_finds_non_compliant(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_control_data(db_session)
        svc = ControlsDomainService(db_session)

        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        assert len(items) > 0
        assert any("CC6.1" in item.summary for item in items)

    def test_get_urgent_items_filters_by_framework(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_control_data(db_session)
        svc = ControlsDomainService(db_session)

        # SOC2 has items
        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        assert len(items) > 0

        # HIPAA has none
        items = svc.get_urgent_items(QueryFilters(frameworks=["hipaa"]))
        assert len(items) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_services.py::TestControlsDomainService -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement ControlsDomainService**

```python
# warlock/domains/controls.py
"""Controls domain service — the central compliance hub."""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, POAM
from warlock.domains.base import (
    DomainEvent,
    QueryFilters,
    RelatedItem,
    UrgentItem,
)

log = logging.getLogger(__name__)

# Severity to numeric for priority scoring
_SEV_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}


class ControlsDomainService:
    """Wraps existing compliance data as a domain service."""

    @property
    def domain_name(self) -> str:
        return "controls"

    def __init__(self, session: Session):
        self._session = session

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        """Non-compliant controls, ranked by severity."""
        q = self._session.query(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.severity,
            func.count(ControlResult.id).label("count"),
        ).filter(
            ControlResult.status == "non_compliant",
        ).group_by(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.severity,
        )

        if filters.frameworks:
            q = q.filter(ControlResult.framework.in_(filters.frameworks))

        rows = q.limit(filters.limit).all()

        items = []
        for fw, ctrl, sev, count in rows:
            score = _SEV_SCORE.get(sev, 10) + min(count, 100)
            items.append(UrgentItem(
                domain="controls",
                entity_type="control",
                entity_id=f"{fw}/{ctrl}",
                summary=f"{ctrl} ({fw}): {count} non-compliant results [{sev}]",
                severity=sev or "medium",
                priority_score=score,
                action_hint=f"warlock control {ctrl} -f {fw}",
                framework=fw,
            ))

        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        """Return control status info for a given entity."""
        if entity_type != "control":
            return []

        control_id = entity_id
        results = (
            self._session.query(ControlResult)
            .filter(ControlResult.control_id == control_id)
            .all()
        )

        if not results:
            return []

        # Aggregate by status
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
                domain="controls",
                entity_type="control_status",
                entity_id=control_id,
                summary=f"Compliant: {compliant}, Non-compliant: {non_compliant}, Total: {total}",
                status="non_compliant" if non_compliant > 0 else "compliant",
                metadata={
                    "by_status": dict(by_status),
                    "frameworks": sorted(frameworks),
                },
            )
        ]

        # Check for linked POAMs
        poams = (
            self._session.query(POAM)
            .filter(POAM.control_id == control_id)
            .all()
        )
        for poam in poams:
            items.append(RelatedItem(
                domain="controls",
                entity_type="poam",
                entity_id=poam.id,
                summary=f"POAM: {poam.weakness[:80] if poam.weakness else 'N/A'} [{poam.status}]",
                severity=poam.severity,
                status=poam.status,
            ))

        return items

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        """React to domain events. Phase 1: no-op. Phase 3: re-assess on issue completion."""
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domain_services.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/domains/controls.py tests/test_domain_services.py
git commit -m "feat(domains): add ControlsDomainService with cross-domain queries"
```

---

### Task 7: Issues Domain Service (Proof of Concept)

**Files:**
- Create: `warlock/domains/issues.py`
- Test: `tests/test_domain_services.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_domain_services.py`:

```python
def _seed_issue_data(session):
    """Seed issues and POAMs for testing."""
    now = datetime.now(timezone.utc)

    poam = POAM(
        framework="nist_800_53", control_id="AC-2",
        severity="critical", status="open",
        weakness="Root account access keys active",
        created_by="admin@acme.com",
        due_date=now - timedelta(days=5),  # overdue
    )
    session.add(poam)

    issue = Issue(
        framework="soc2", control_id="CC6.1",
        title="MFA not enforced",
        status="open", priority="high",
    )
    session.add(issue)

    session.commit()
    return {"poam": poam, "issue": issue}


class TestIssuesDomainService:
    def test_domain_name(self):
        from warlock.domains.issues import IssuesDomainService

        svc = IssuesDomainService.__new__(IssuesDomainService)
        assert svc.domain_name == "issues"

    def test_get_urgent_items_includes_overdue_poams(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        data = _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)

        items = svc.get_urgent_items(QueryFilters())
        assert len(items) >= 1
        # The overdue POAM should be highest priority
        overdue = [i for i in items if "overdue" in i.summary.lower() or "AC-2" in i.summary]
        assert len(overdue) >= 1

    def test_get_related_to_control(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)

        related = svc.get_related_to("control", "AC-2")
        assert len(related) >= 1
        assert related[0].entity_type in ("poam", "issue")

    def test_get_urgent_items_filters_framework(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)

        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        # Should only get the SOC2 issue, not the NIST POAM
        for item in items:
            assert "soc2" in item.entity_id or item.framework == "soc2"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_services.py::TestIssuesDomainService -v`
Expected: FAIL

- [ ] **Step 3: Implement IssuesDomainService**

```python
# warlock/domains/issues.py
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

log = logging.getLogger(__name__)

_SEV_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
_PRIO_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25}


class IssuesDomainService:
    """Unified view of POAMs and Issues as remediation work items."""

    @property
    def domain_name(self) -> str:
        return "issues"

    def __init__(self, session: Session):
        self._session = session

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        """Open/overdue POAMs and Issues, ranked by urgency."""
        now = datetime.now(timezone.utc)
        items: list[UrgentItem] = []

        # POAMs
        pq = self._session.query(POAM).filter(
            POAM.status.in_(["draft", "open", "in_progress"])
        )
        if filters.frameworks:
            pq = pq.filter(POAM.framework.in_(filters.frameworks))

        for poam in pq.limit(filters.limit).all():
            score = _SEV_SCORE.get(poam.severity, 10)
            overdue_label = ""
            if poam.due_date and poam.due_date < now:
                days_overdue = (now - poam.due_date).days
                score += min(days_overdue * 5, 100)  # overdue boosts priority
                overdue_label = f" — overdue {days_overdue}d"

            items.append(UrgentItem(
                domain="issues",
                entity_type="poam",
                entity_id=f"poam/{poam.id[:8]}",
                summary=f"POAM {poam.control_id} ({poam.framework}): "
                        f"{poam.weakness[:60] if poam.weakness else 'N/A'}"
                        f" [{poam.severity}]{overdue_label}",
                severity=poam.severity or "medium",
                priority_score=score,
                sla_deadline=poam.due_date,
                framework=poam.framework,
                action_hint=f"warlock remediate {poam.id[:8]}",
            ))

        # Issues
        iq = self._session.query(Issue).filter(
            Issue.status.in_(["open", "assigned", "in_progress"])
        )
        if filters.frameworks:
            iq = iq.filter(Issue.framework.in_(filters.frameworks))

        for issue in iq.limit(filters.limit).all():
            score = _PRIO_SCORE.get(issue.priority, 10)
            items.append(UrgentItem(
                domain="issues",
                entity_type="issue",
                entity_id=f"issue/{issue.id[:8]}",
                summary=f"Issue {issue.control_id} ({issue.framework}): "
                        f"{issue.title[:60] if issue.title else 'N/A'}"
                        f" [{issue.priority}]",
                severity=issue.priority or "medium",
                priority_score=score,
                framework=issue.framework,
                assigned_to=issue.assigned_to,
                action_hint=f"warlock remediate {issue.id[:8]}",
            ))

        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        """Find POAMs and Issues related to a control."""
        if entity_type != "control":
            return []

        items: list[RelatedItem] = []

        for poam in self._session.query(POAM).filter(POAM.control_id == entity_id).all():
            items.append(RelatedItem(
                domain="issues",
                entity_type="poam",
                entity_id=poam.id[:8],
                summary=f"POAM: {poam.weakness[:80] if poam.weakness else 'N/A'}",
                severity=poam.severity,
                status=poam.status,
            ))

        for issue in self._session.query(Issue).filter(Issue.control_id == entity_id).all():
            items.append(RelatedItem(
                domain="issues",
                entity_type="issue",
                entity_id=issue.id[:8],
                summary=f"Issue: {issue.title[:80] if issue.title else 'N/A'}",
                severity=issue.priority,
                status=issue.status,
            ))

        return items

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        """Phase 1: no-op. Phase 3: auto-create issues from findings."""
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domain_services.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/domains/issues.py tests/test_domain_services.py
git commit -m "feat(domains): add IssuesDomainService — unified POAMs + Issues"
```

---

### Task 8: Evidence Domain Service (Proof of Concept)

**Files:**
- Create: `warlock/domains/evidence.py`
- Test: `tests/test_domain_services.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_domain_services.py`:

```python
class TestEvidenceDomainService:
    def test_domain_name(self):
        from warlock.domains.evidence import EvidenceDomainService

        svc = EvidenceDomainService.__new__(EvidenceDomainService)
        assert svc.domain_name == "evidence"

    def test_get_related_to_control(self, db_session):
        from warlock.domains.evidence import EvidenceDomainService

        now = datetime.now(timezone.utc)
        # Add a finding (evidence of assessment)
        re = RawEvent(
            connector_name="demo-aws", source="aws", source_type="cloud",
            event_type="iam_user", payload={"test": True},
            sha256="rawhash1", collected_at=now,
        )
        db_session.add(re)
        db_session.flush()

        f = Finding(
            raw_event_id=re.id,
            observation_type="configuration",
            title="IAM user without MFA",
            source="aws", source_type="cloud", provider="aws",
            severity="high", confidence=1.0,
            observed_at=now, ingested_at=now,
            sha256="hash1",
        )
        db_session.add(f)

        # Map finding to control
        cm = ControlMapping(
            finding_id=f.id, framework="soc2", control_id="CC6.1",
        )
        db_session.add(cm)
        db_session.commit()

        svc = EvidenceDomainService(db_session)
        related = svc.get_related_to("control", "CC6.1")
        assert len(related) >= 1
        assert any(r.entity_type == "evidence_summary" for r in related)

    def test_get_urgent_items_finds_stale_evidence(self, db_session):
        from warlock.domains.evidence import EvidenceDomainService

        # Add a control result from 100 days ago (stale)
        old = datetime.now(timezone.utc) - timedelta(days=100)
        cr = ControlResult(
            framework="soc2", control_id="CC6.1",
            status="compliant", severity="medium",
            assessor="assertion:mfa_enabled",
            finding_id="f-old",
            assessed_at=old,
            detail={}, sha256="oldhash",
        )
        db_session.add(cr)
        db_session.commit()

        svc = EvidenceDomainService(db_session, stale_threshold_days=90)
        items = svc.get_urgent_items(QueryFilters())
        # Should flag CC6.1 as having stale evidence
        assert len(items) >= 1
        assert any("stale" in item.summary.lower() or "CC6.1" in item.summary for item in items)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_services.py::TestEvidenceDomainService -v`
Expected: FAIL

- [ ] **Step 3: Implement EvidenceDomainService**

```python
# warlock/domains/evidence.py
"""Evidence domain service — freshness, sufficiency, and evidence lifecycle."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlMapping, ControlResult, Finding
from warlock.domains.base import (
    DomainEvent,
    QueryFilters,
    RelatedItem,
    UrgentItem,
)

log = logging.getLogger(__name__)


class EvidenceDomainService:
    """Wraps evidence freshness and sufficiency as a domain service."""

    @property
    def domain_name(self) -> str:
        return "evidence"

    def __init__(self, session: Session, stale_threshold_days: int = 90):
        self._session = session
        self._stale_days = stale_threshold_days

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        """Controls with stale evidence (last assessed > threshold days ago)."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._stale_days)

        # Find controls where the most recent assessment is older than cutoff
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
            days_ago = (now - last).days if last else 999
            items.append(UrgentItem(
                domain="evidence",
                entity_type="stale_evidence",
                entity_id=f"{fw}/{ctrl}",
                summary=f"{ctrl} ({fw}): evidence stale — last assessed {days_ago}d ago (threshold: {self._stale_days}d)",
                severity="medium",
                priority_score=30 + min(days_ago - self._stale_days, 50),
                action_hint=f"warlock evidence refresh --control {ctrl} -f {fw}",
                framework=fw,
            ))

        return items

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        """Evidence summary for a control."""
        if entity_type != "control":
            return []

        control_id = entity_id

        # Count findings mapped to this control
        finding_count = (
            self._session.query(func.count(ControlMapping.id))
            .filter(ControlMapping.control_id == control_id)
            .scalar()
        ) or 0

        # Most recent assessment
        latest = (
            self._session.query(func.max(ControlResult.assessed_at))
            .filter(ControlResult.control_id == control_id)
            .scalar()
        )

        if finding_count == 0 and latest is None:
            return []

        now = datetime.now(timezone.utc)
        days_ago = (now - latest).days if latest else None
        stale = days_ago is not None and days_ago > self._stale_days
        freshness = "stale" if stale else "current" if days_ago is not None else "unknown"

        return [RelatedItem(
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
        )]

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        """Phase 1: no-op. Phase 3: emit evidence.stale events."""
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_domain_services.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/domains/evidence.py tests/test_domain_services.py
git commit -m "feat(domains): add EvidenceDomainService — freshness and sufficiency"
```

---

### Task 9: CLI — `warlock policy` Command

**Files:**
- Create: `warlock/cli/policy_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)
- Test: `tests/test_domain_cli.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_domain_cli.py
"""CLI integration tests for domain commands."""

from click.testing import CliRunner
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.cli import cli
from warlock.db.models import Base

import pytest
import os


@pytest.fixture(autouse=True)
def _use_test_db(tmp_path, monkeypatch):
    """Point Warlock at a temp SQLite DB for CLI tests."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("WLK_DATABASE_URL", f"sqlite:///{db_path}")
    # Force engine re-creation
    import warlock.db.engine as eng
    eng._engine = None
    eng._read_engine = None
    from warlock.db.engine import init_db
    init_db()
    yield


class TestPolicyCLI:
    def test_policy_list_empty(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "No policies" in result.output or "policies" in result.output.lower()

    def test_policy_set_sla(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "set", "sla",
            "--severity", "critical",
            "--remediation-days", "14",
            "--escalate-after", "7",
        ])
        assert result.exit_code == 0
        assert "created" in result.output.lower() or "set" in result.output.lower()

        # Verify it appears in list
        result = runner.invoke(cli, ["policy", "list"])
        assert "sla" in result.output.lower()

    def test_policy_set_retention(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "set", "retention",
            "--framework", "pci_dss",
            "--days", "2555",
        ])
        assert result.exit_code == 0

    def test_policy_show_control(self):
        runner = CliRunner()
        # Set a policy first
        runner.invoke(cli, [
            "policy", "set", "sla",
            "--severity", "critical",
            "--remediation-days", "14",
        ])
        result = runner.invoke(cli, ["policy", "show", "--control", "AC-2"])
        assert result.exit_code == 0

    def test_policy_history(self):
        runner = CliRunner()
        runner.invoke(cli, [
            "policy", "set", "sla",
            "--severity", "critical",
            "--remediation-days", "14",
        ])
        result = runner.invoke(cli, ["policy", "history"])
        assert result.exit_code == 0
        assert "created" in result.output.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `warlock policy` CLI**

```python
# warlock/cli/policy_cmd.py
"""CLI commands for the unified policy engine."""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console


@cli.group()
def policy():
    """Push and manage operational policies."""
    pass


@policy.command("set")
@click.argument("policy_type", type=click.Choice([
    "sla", "retention", "classification", "risk-appetite",
    "escalation", "auto-assign", "auto-create", "cadence",
    "confidence", "evidence-requirement", "pii",
]))
@click.option("--framework", "-f", default=None, help="Scope to framework")
@click.option("--severity", default=None, help="Scope to severity level")
@click.option("--remediation-days", type=int, default=None, help="SLA: days to remediate")
@click.option("--escalate-after", type=int, default=None, help="SLA: escalate after N days")
@click.option("--days", type=int, default=None, help="Retention: days to keep data")
@click.option("--owner", default=None, help="Auto-assign: owner email")
@click.option("--frequency", default=None, help="Cadence: monitoring frequency")
@click.option("--floor", type=float, default=None, help="Confidence: minimum AI confidence")
@click.option("--max-ale", type=int, default=None, help="Risk appetite: max ALE in dollars")
@click.option("--max-var95", type=int, default=None, help="Risk appetite: max VaR95 in dollars")
@click.option("--priority", type=int, default=0, help="Policy priority (higher wins)")
@click.option("--reason", default="", help="Description / reason for this policy")
@click.option("--actor", default=None, help="Actor identity (default: cli@warlock)")
@click.option("--dry-run", is_flag=True, help="Show what would change without executing")
def policy_set(
    policy_type, framework, severity, remediation_days, escalate_after,
    days, owner, frequency, floor, max_ale, max_var95, priority, reason,
    actor, dry_run,
):
    """Push a policy to the system."""
    import os
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    actor = actor or os.environ.get("WLK_CLI_ACTOR", "cli@warlock")

    # Build scope
    scope = {}
    if framework:
        scope["frameworks"] = [framework]
    if severity:
        scope["severity"] = [severity]

    # Build rules based on policy type
    rules = {}
    if policy_type == "sla":
        if remediation_days is not None:
            rules["remediation_days"] = remediation_days
        if escalate_after is not None:
            rules["escalate_after"] = escalate_after
    elif policy_type == "retention":
        if days is not None:
            rules["days"] = days
    elif policy_type == "auto-assign":
        if owner:
            rules["owner"] = owner
    elif policy_type == "cadence":
        if frequency:
            rules["frequency"] = frequency
    elif policy_type == "confidence":
        if floor is not None:
            rules["floor"] = floor
    elif policy_type == "risk-appetite":
        if max_ale is not None:
            rules["max_ale"] = max_ale
        if max_var95 is not None:
            rules["max_var95"] = max_var95
    # Other types: store whatever options were provided
    if not rules:
        console.print("[red]No rules specified. Use --help to see options for this policy type.[/red]")
        raise SystemExit(1)

    if dry_run:
        console.print(f"[dim]DRY RUN: Would create {policy_type} policy[/dim]")
        console.print(f"  Scope: {scope or 'global'}")
        console.print(f"  Rules: {rules}")
        return

    with get_session() as session:
        engine = PolicyEngine(session)
        p = engine.set_policy(
            policy_type=policy_type.replace("-", "_"),
            scope=scope,
            rules=rules,
            actor=actor,
            priority=priority,
            description=reason,
        )
        console.print(f"[green]Policy created:[/green] {policy_type} (id: {p.id[:8]})")
        console.print(f"  Scope: {scope or 'global'}")
        console.print(f"  Rules: {rules}")


@policy.command("list")
@click.option("--type", "policy_type", default=None, help="Filter by policy type")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def policy_list(policy_type, framework):
    """List active policies."""
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    with get_session() as session:
        engine = PolicyEngine(session)
        policies = engine.list_policies(
            policy_type=policy_type.replace("-", "_") if policy_type else None,
            framework=framework,
        )

    if not policies:
        console.print("[dim]No policies found.[/dim]")
        return

    table = Table(title=f"Policies ({len(policies)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Rules")
    table.add_column("Priority", justify="right")
    table.add_column("Created By")

    for p in policies:
        scope_str = str(p.scope) if p.scope else "global"
        if len(scope_str) > 40:
            scope_str = scope_str[:37] + "..."
        rules_str = str(p.rules)
        if len(rules_str) > 40:
            rules_str = rules_str[:37] + "..."
        table.add_row(
            p.id[:8], p.policy_type, scope_str, rules_str,
            str(p.priority), p.created_by,
        )

    console.print(table)


@policy.command("show")
@click.option("--control", default=None, help="Show policies affecting a control")
@click.option("--framework", "-f", default=None, help="Show policies for a framework")
def policy_show(control, framework):
    """Show policies affecting a specific entity."""
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    with get_session() as session:
        engine = PolicyEngine(session)
        policies = engine.list_policies(framework=framework)

    if not policies:
        console.print("[dim]No matching policies.[/dim]")
        return

    for p in policies:
        console.print(f"[bold]{p.policy_type}[/bold] (priority: {p.priority})")
        console.print(f"  Scope: {p.scope or 'global'}")
        console.print(f"  Rules: {p.rules}")
        console.print(f"  By: {p.created_by}  |  {p.description or ''}")
        console.print()


@policy.command("history")
@click.option("--type", "policy_type", default=None, help="Filter by type")
@click.option("--limit", "-n", default=20, help="Max entries")
def policy_history(policy_type, limit):
    """Show policy change history."""
    from warlock.db.engine import get_session
    from warlock.db.models import PolicyHistory, Policy

    with get_session() as session:
        q = session.query(PolicyHistory).join(Policy)
        if policy_type:
            q = q.filter(Policy.policy_type == policy_type.replace("-", "_"))
        rows = q.order_by(PolicyHistory.timestamp.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No policy history.[/dim]")
        return

    table = Table(title="Policy History")
    table.add_column("Timestamp")
    table.add_column("Action")
    table.add_column("Type")
    table.add_column("Actor")
    table.add_column("Rules")

    for h in rows:
        table.add_row(
            str(h.timestamp)[:19] if h.timestamp else "",
            h.action,
            h.policy.policy_type if h.policy else "",
            h.actor,
            str(h.new_rules)[:50],
        )

    console.print(table)
```

- [ ] **Step 4: Register the policy command in `warlock/cli/__init__.py`**

Add after the existing imports (line ~174):
```python
from warlock.cli import policy_cmd as _policy_cmd  # noqa: F401, E402
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_domain_cli.py -v`
Expected: All tests PASS

- [ ] **Step 6: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ pass, 0 fail

- [ ] **Step 7: Commit**

```bash
git add warlock/cli/policy_cmd.py warlock/cli/__init__.py tests/test_domain_cli.py
git commit -m "feat(cli): add warlock policy set/list/show/history commands"
```

---

### Task 10: CLI — `warlock briefing` Command

**Files:**
- Create: `warlock/cli/briefing_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)
- Test: `tests/test_domain_cli.py` (append)

- [ ] **Step 1: Write failing test**

Append to `tests/test_domain_cli.py`:

```python
class TestBriefingCLI:
    def test_briefing_runs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing"])
        assert result.exit_code == 0
        assert "briefing" in result.output.lower() or "warlock" in result.output.lower()

    def test_briefing_with_framework_filter(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing", "-f", "soc2"])
        assert result.exit_code == 0

    def test_briefing_with_mode(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing", "--mode", "audit-prep"])
        assert result.exit_code == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_cli.py::TestBriefingCLI -v`
Expected: FAIL

- [ ] **Step 3: Implement `warlock briefing` CLI**

```python
# warlock/cli/briefing_cmd.py
"""CLI command: warlock briefing — cross-domain daily priority view."""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import cli, console


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--owner", default=None, help="Filter by assignee")
@click.option("--mode", default="steady-state",
              type=click.Choice(["steady-state", "audit-prep", "remediation-sprint", "incident-response"]),
              help="Operational mode — changes what gets surfaced")
@click.option("--limit", "-n", default=30, help="Max items per section")
def briefing(framework, owner, mode, limit):
    """Daily briefing — what needs attention across all domains."""
    from warlock.db.engine import get_session
    from warlock.domains.base import QueryFilters
    from warlock.domains.registry import DomainRegistry
    from warlock.domains.controls import ControlsDomainService
    from warlock.domains.issues import IssuesDomainService
    from warlock.domains.evidence import EvidenceDomainService

    now = datetime.now(timezone.utc)
    filters = QueryFilters(
        frameworks=[framework] if framework else None,
        owner=owner,
        mode=mode,
        limit=limit,
    )

    with get_session() as session:
        # Build registry with available services
        registry = DomainRegistry()
        registry.register(ControlsDomainService(session))
        registry.register(IssuesDomainService(session))
        registry.register(EvidenceDomainService(session))

        items = registry.get_briefing(filters)

    # Header
    fw_label = f" — {framework}" if framework else ""
    console.print(Panel(
        f"[bold]Warlock Daily Briefing[/bold] — {now.strftime('%Y-%m-%d')} (mode: {mode}){fw_label}",
        style="cyan",
    ))

    if not items:
        console.print("[dim]Nothing urgent. All clear.[/dim]")
        return

    # Group by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda i: (sev_order.get(i.severity, 5), -i.priority_score))

    # Render sections
    sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}

    table = Table(show_header=True, show_lines=False, pad_edge=False)
    table.add_column("Sev", style="bold", max_width=8)
    table.add_column("Domain", style="dim", max_width=10)
    table.add_column("Summary", min_width=40)
    table.add_column("Action", style="cyan", max_width=40)

    for item in items[:limit]:
        sev_style = sev_colors.get(item.severity, "")
        table.add_row(
            f"[{sev_style}]{item.severity.upper()[:4]}[/{sev_style}]",
            item.domain,
            item.summary[:80],
            item.action_hint,
        )

    console.print(table)
    console.print(f"\n[dim]{len(items)} items total. Use -f/--owner/--mode to filter.[/dim]")
```

- [ ] **Step 4: Register in `warlock/cli/__init__.py`**

Add:
```python
from warlock.cli import briefing_cmd as _briefing_cmd  # noqa: F401, E402
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_domain_cli.py -v`
Expected: All PASS

- [ ] **Step 6: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ pass

- [ ] **Step 7: Commit**

```bash
git add warlock/cli/briefing_cmd.py warlock/cli/__init__.py tests/test_domain_cli.py
git commit -m "feat(cli): add warlock briefing — cross-domain daily priority view"
```

---

### Task 11: CLI — `warlock control` Cross-Domain Hub

**Files:**
- Create: `warlock/cli/control_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)
- Test: `tests/test_domain_cli.py` (append)

- [ ] **Step 1: Write failing test**

Append to `tests/test_domain_cli.py`:

```python
class TestControlCLI:
    def test_control_hub_runs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["control-hub", "AC-2", "-f", "nist_800_53"])
        assert result.exit_code == 0

    def test_control_hub_no_data(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["control-hub", "FAKE-99", "-f", "fake"])
        assert result.exit_code == 0
        assert "no data" in result.output.lower() or "not found" in result.output.lower() or result.output
```

Note: we use `control-hub` to avoid conflicting with the existing `control` command. This can be renamed or the old command replaced in Phase 2.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_domain_cli.py::TestControlCLI -v`
Expected: FAIL

- [ ] **Step 3: Implement `warlock control-hub`**

```python
# warlock/cli/control_cmd.py
"""CLI command: warlock control-hub — cross-domain control view."""

from __future__ import annotations

import click
from rich.panel import Panel

from warlock.cli import cli, console


@cli.command("control-hub")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework context")
def control_hub(control_id, framework):
    """Cross-domain view of a control: status, evidence, issues, risk, owner."""
    from warlock.db.engine import get_session
    from warlock.domains.registry import DomainRegistry
    from warlock.domains.controls import ControlsDomainService
    from warlock.domains.issues import IssuesDomainService
    from warlock.domains.evidence import EvidenceDomainService

    with get_session() as session:
        registry = DomainRegistry()
        registry.register(ControlsDomainService(session))
        registry.register(IssuesDomainService(session))
        registry.register(EvidenceDomainService(session))

        related = registry.get_related_to("control", control_id)

    if not related:
        console.print(f"[dim]No data found for control {control_id}.[/dim]")
        return

    # Header
    fw_label = f" ({framework})" if framework else ""
    console.print(Panel(
        f"[bold]Control: {control_id}{fw_label}[/bold]",
        style="cyan",
    ))

    # Render each domain's contribution
    domain_labels = {
        "controls": "Compliance Status",
        "issues": "Open Issues & POAMs",
        "evidence": "Evidence",
        "risk": "Risk",
        "personnel": "Ownership",
    }

    for domain_name, items in related.items():
        label = domain_labels.get(domain_name, domain_name.title())
        console.print(f"\n[bold]{label}:[/bold]")
        for item in items:
            severity_str = f" [{item.severity}]" if item.severity else ""
            status_str = f" ({item.status})" if item.status else ""
            console.print(f"  {item.summary}{severity_str}{status_str}")

    # Action hints
    console.print(f"\n[dim]Actions:[/dim]")
    console.print(f"  warlock remediate <issue-id>")
    console.print(f"  warlock evidence refresh --control {control_id}")
    if framework:
        console.print(f"  warlock risk analyze -f {framework}")
```

- [ ] **Step 4: Register in `warlock/cli/__init__.py`**

Add:
```python
from warlock.cli import control_cmd as _control_cmd  # noqa: F401, E402
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_domain_cli.py -v`
Expected: All PASS

- [ ] **Step 6: Run full test suite + demo seed**

Run: `pytest --tb=short -q`
Expected: 556+ pass

Run demo seed to verify nothing broke:
```bash
rm -f warlock.db /tmp/warlock_pipeline.lock "${TMPDIR}/warlock_pipeline.lock"
.venv/bin/python scripts/demo_seed.py 2>/dev/null | grep -E 'succeed|fail|Raw events|Finding|Controls mapped'
```
Expected: 81 succeeded, 0 failed, 358 raw events, 5,008 findings, 373,852 mappings

- [ ] **Step 7: Commit**

```bash
git add warlock/cli/control_cmd.py warlock/cli/__init__.py tests/test_domain_cli.py
git commit -m "feat(cli): add warlock control-hub — cross-domain control view"
```

---

### Task 12: Integration Smoke Test — Full Cross-Domain Workflow

**Files:**
- Test: `tests/test_domain_cli.py` (append)

This is the final acceptance test: seed data, run briefing, run control-hub, set a policy — verify the whole flow works end-to-end.

- [ ] **Step 1: Write integration test**

Append to `tests/test_domain_cli.py`:

```python
class TestCrossDomainIntegration:
    """End-to-end: seed data, then use cross-domain commands."""

    def _seed_test_data(self):
        """Seed minimal control results, POAMs, and issues for integration testing."""
        from warlock.db.engine import get_session
        from warlock.db.models import ControlResult, POAM, Issue
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        with get_session() as session:
            # Non-compliant control
            session.add(ControlResult(
                framework="soc2", control_id="CC6.1",
                status="non_compliant", severity="critical",
                assessor="assertion:mfa_enabled", finding_id="f-1",
                assessed_at=now, detail={}, sha256="test1",
            ))
            # Overdue POAM
            session.add(POAM(
                framework="soc2", control_id="CC6.1",
                severity="critical", status="open",
                weakness="MFA not enforced",
                created_by="admin@acme.com",
                due_date=now - timedelta(days=3),
            ))
            # Open issue
            session.add(Issue(
                framework="soc2", control_id="CC6.1",
                title="Enforce MFA for all users",
                status="open", priority="critical",
            ))
            session.commit()

    def test_full_workflow(self):
        """Seed → briefing → control-hub → policy set → policy list."""
        self._seed_test_data()
        runner = CliRunner()

        # 1. Briefing shows urgent items
        result = runner.invoke(cli, ["briefing", "-f", "soc2"])
        assert result.exit_code == 0
        assert "CC6.1" in result.output

        # 2. Control hub shows cross-domain data
        result = runner.invoke(cli, ["control-hub", "CC6.1", "-f", "soc2"])
        assert result.exit_code == 0
        assert "CC6.1" in result.output

        # 3. Set an SLA policy
        result = runner.invoke(cli, [
            "policy", "set", "sla",
            "--severity", "critical",
            "--remediation-days", "14",
            "--escalate-after", "7",
        ])
        assert result.exit_code == 0
        assert "created" in result.output.lower()

        # 4. Policy appears in list
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "sla" in result.output.lower()

        # 5. Policy history recorded
        result = runner.invoke(cli, ["policy", "history"])
        assert result.exit_code == 0
        assert "created" in result.output.lower()
```

- [ ] **Step 2: Run integration test**

Run: `pytest tests/test_domain_cli.py::TestCrossDomainIntegration -v`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `pytest --tb=short -q`
Expected: 556+ existing tests pass + all new domain tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/test_domain_cli.py
git commit -m "test(domains): add cross-domain integration smoke test"
```

---

## Post-Phase 1 Verification

After all 12 tasks are complete, verify:

1. `pytest --tb=short -q` — all tests pass (existing + new)
2. Demo seed still works: `rm -f warlock.db && .venv/bin/python scripts/demo_seed.py 2>/dev/null | grep -E 'succeed|fail'`
3. New commands work against seeded data:
   - `warlock briefing`
   - `warlock briefing -f soc2`
   - `warlock control-hub CC6.1 -f soc2`
   - `warlock policy set sla --severity critical --remediation-days 14`
   - `warlock policy list`
   - `warlock policy history`
4. Existing commands still work: `warlock coverage`, `warlock results`, `warlock poams`
