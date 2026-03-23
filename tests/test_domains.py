"""Tests for domain infrastructure: base classes, registry, event bus."""


class TestDomainDataclasses:
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
        assert scope.frameworks is None
        assert scope.severity is None


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
        reg.register(
            FakeService(
                "risk",
                related=[
                    RelatedItem(
                        domain="risk", entity_type="score", entity_id="1", summary="$3.5M ALE"
                    )
                ],
            )
        )
        reg.register(
            FakeService(
                "evidence",
                related=[
                    RelatedItem(
                        domain="evidence", entity_type="status", entity_id="2", summary="stale"
                    )
                ],
            )
        )
        reg.register(FakeService("empty"))
        result = reg.get_related_to("control", "AC-2")
        assert "risk" in result
        assert "evidence" in result
        assert "empty" not in result
        assert len(result) == 2

    def test_get_briefing_sorts_by_priority(self):
        from warlock.domains.base import UrgentItem
        from warlock.domains.registry import DomainRegistry

        reg = DomainRegistry()
        reg.register(
            FakeService(
                "a",
                urgent=[
                    UrgentItem(
                        domain="a",
                        entity_type="x",
                        entity_id="1",
                        summary="low",
                        severity="low",
                        priority_score=10.0,
                        action_hint="fix it",
                    )
                ],
            )
        )
        reg.register(
            FakeService(
                "b",
                urgent=[
                    UrgentItem(
                        domain="b",
                        entity_type="x",
                        entity_id="2",
                        summary="high",
                        severity="critical",
                        priority_score=95.0,
                        action_hint="fix it now",
                    )
                ],
            )
        )
        items = reg.get_briefing()
        assert items[0].priority_score == 95.0
        assert items[1].priority_score == 10.0


class TestDomainEventBus:
    def test_publish_and_subscribe(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        received = []
        bus = DomainEventBus()
        bus.subscribe("issue.completed", lambda e: received.append(e))
        evt = DomainEvent(
            event_type="issue.completed",
            domain="issues",
            entity_type="issue",
            entity_id="1",
            actor="test",
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
                return [
                    DomainEvent(
                        event_type="control.reassessed",
                        domain="assessment",
                        entity_type="control",
                        entity_id="AC-2",
                        actor="system",
                        correlation_id=event.correlation_id,
                    )
                ]
            return []

        bus = DomainEventBus()
        bus.subscribe("issue.completed", handler)
        bus.subscribe("control.reassessed", lambda e: cascade_log.append(e.event_type))
        evt = DomainEvent(
            event_type="issue.completed",
            domain="issues",
            entity_type="issue",
            entity_id="1",
            actor="test",
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
            return [
                DomainEvent(
                    event_type="loop.event",
                    domain="test",
                    entity_type="x",
                    entity_id="1",
                    actor="test",
                    correlation_id=event.correlation_id,
                )
            ]

        bus = DomainEventBus(max_cascade_depth=5)
        bus.subscribe("loop.event", looping_handler)
        bus.publish(
            DomainEvent(
                event_type="loop.event",
                domain="test",
                entity_type="x",
                entity_id="1",
                actor="test",
            )
        )
        assert call_count == 5

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
            event_type="test.event",
            domain="a",
            entity_type="x",
            entity_id="1",
            actor="test",
            correlation_id=corr_id,
        )
        evt2 = DomainEvent(
            event_type="test.event",
            domain="b",
            entity_type="x",
            entity_id="1",
            actor="test",
            correlation_id=corr_id,
        )
        bus.publish(evt1)
        bus.publish_cascade(evt2, corr_id, depth=1)
        assert call_count == 1

    def test_wildcard_subscription(self):
        from warlock.domains.base import DomainEvent
        from warlock.domains.bus import DomainEventBus

        received = []
        bus = DomainEventBus()
        bus.subscribe_all(lambda e: received.append(e.event_type))
        bus.publish(
            DomainEvent(
                event_type="a.happened", domain="a", entity_type="x", entity_id="1", actor="test"
            )
        )
        bus.publish(
            DomainEvent(
                event_type="b.happened", domain="b", entity_type="x", entity_id="2", actor="test"
            )
        )
        assert len(received) == 2
