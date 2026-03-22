"""Tests for domain infrastructure: base classes, registry, event bus."""

from datetime import datetime, timezone

import pytest


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
            domain="risk", entity_type="risk_score", entity_id="rs-123",
            summary="ALE $3.5M for AC-2", severity="high",
        )
        assert item.domain == "risk"
        assert item.severity == "high"
        assert item.metadata is None

    def test_urgent_item_creation(self):
        from warlock.domains.base import UrgentItem
        item = UrgentItem(
            domain="issues", entity_type="poam", entity_id="POAM-123",
            summary="Root access keys active", severity="critical",
            priority_score=95.0,
            action_hint="warlock issue transition POAM-123 --to in_progress",
        )
        assert item.priority_score == 95.0
        assert item.action_hint.startswith("warlock")

    def test_domain_event_creation(self):
        from warlock.domains.base import DomainEvent
        evt = DomainEvent(
            event_type="issue.completed", domain="issues",
            entity_type="issue", entity_id="ISS-456",
            actor="eve@acme.com", payload={"control": "AC-2"},
        )
        assert evt.event_type == "issue.completed"
        assert evt.correlation_id  # auto-generated
        assert evt.timestamp  # auto-generated

    def test_policy_scope_matches_all_when_empty(self):
        from warlock.domains.base import PolicyScope
        scope = PolicyScope()
        assert scope.frameworks is None
        assert scope.severity is None
