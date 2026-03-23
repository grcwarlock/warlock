"""Tests for warlock.pipeline.schema_registry (OPS-7)."""

from __future__ import annotations

import logging

import pytest

from warlock.connectors.base import RawEventData, SourceType
from warlock.pipeline.schema_registry import (
    EventTypeSchema,
    SchemaRegistry,
    _extract_event_types_from_module,
    _guess_provider_from_module,
    build_registry_from_connectors,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> SchemaRegistry:
    return SchemaRegistry()


@pytest.fixture
def aws_schema() -> EventTypeSchema:
    return EventTypeSchema(
        source="aws",
        provider="aws",
        event_type="iam_credential_report",
        description="IAM credential report for all users",
        required_fields=["response"],
        normalizer_class="AWSNormalizer",
    )


@pytest.fixture
def raw_event_valid() -> RawEventData:
    return RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="iam_credential_report",
        raw_data={"response": {"users": []}},
    )


@pytest.fixture
def raw_event_missing_field() -> RawEventData:
    return RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="iam_credential_report",
        raw_data={"other_key": "value"},
    )


@pytest.fixture
def raw_event_unregistered() -> RawEventData:
    return RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="nonexistent_check",
        raw_data={"foo": "bar"},
    )


# ---------------------------------------------------------------------------
# EventTypeSchema
# ---------------------------------------------------------------------------


class TestEventTypeSchema:
    def test_frozen(self, aws_schema: EventTypeSchema) -> None:
        with pytest.raises(AttributeError):
            aws_schema.source = "gcp"  # type: ignore[misc]

    def test_fields(self, aws_schema: EventTypeSchema) -> None:
        assert aws_schema.source == "aws"
        assert aws_schema.provider == "aws"
        assert aws_schema.event_type == "iam_credential_report"
        assert aws_schema.required_fields == ["response"]
        assert aws_schema.normalizer_class == "AWSNormalizer"

    def test_defaults(self) -> None:
        schema = EventTypeSchema(
            source="gcp",
            provider="gcp",
            event_type="compute_instances",
            description="GCP compute instances",
        )
        assert schema.required_fields == []
        assert schema.normalizer_class is None


# ---------------------------------------------------------------------------
# SchemaRegistry
# ---------------------------------------------------------------------------


class TestSchemaRegistry:
    def test_register_and_get(self, registry: SchemaRegistry, aws_schema: EventTypeSchema) -> None:
        registry.register(aws_schema)
        result = registry.get_schema("aws", "iam_credential_report")
        assert result is aws_schema

    def test_get_missing(self, registry: SchemaRegistry) -> None:
        assert registry.get_schema("aws", "nonexistent") is None

    def test_count(self, registry: SchemaRegistry, aws_schema: EventTypeSchema) -> None:
        assert registry.count == 0
        registry.register(aws_schema)
        assert registry.count == 1

    def test_list_all(self, registry: SchemaRegistry) -> None:
        s1 = EventTypeSchema(source="aws", provider="aws", event_type="e1", description="d1")
        s2 = EventTypeSchema(source="gcp", provider="gcp", event_type="e2", description="d2")
        registry.register(s1)
        registry.register(s2)
        assert len(registry.list_schemas()) == 2

    def test_list_filtered(self, registry: SchemaRegistry) -> None:
        s1 = EventTypeSchema(source="aws", provider="aws", event_type="e1", description="d1")
        s2 = EventTypeSchema(source="gcp", provider="gcp", event_type="e2", description="d2")
        registry.register(s1)
        registry.register(s2)
        aws_schemas = registry.list_schemas(source="aws")
        assert len(aws_schemas) == 1
        assert aws_schemas[0].source == "aws"

    def test_overwrite_logs_debug(
        self,
        registry: SchemaRegistry,
        aws_schema: EventTypeSchema,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        registry.register(aws_schema)
        replacement = EventTypeSchema(
            source="aws",
            provider="aws",
            event_type="iam_credential_report",
            description="Updated description",
        )
        with caplog.at_level(logging.DEBUG):
            registry.register(replacement)
        assert "Overwriting schema" in caplog.text
        assert registry.get_schema("aws", "iam_credential_report") is replacement


# ---------------------------------------------------------------------------
# validate_event
# ---------------------------------------------------------------------------


class TestValidateEvent:
    def test_valid_event(
        self,
        registry: SchemaRegistry,
        aws_schema: EventTypeSchema,
        raw_event_valid: RawEventData,
    ) -> None:
        registry.register(aws_schema)
        errors = registry.validate_event(raw_event_valid)
        assert errors == []

    def test_unregistered_event_type(
        self,
        registry: SchemaRegistry,
        raw_event_unregistered: RawEventData,
    ) -> None:
        errors = registry.validate_event(raw_event_unregistered)
        assert len(errors) == 1
        assert "Unregistered event_type" in errors[0]

    def test_missing_required_field(
        self,
        registry: SchemaRegistry,
        aws_schema: EventTypeSchema,
        raw_event_missing_field: RawEventData,
    ) -> None:
        registry.register(aws_schema)
        errors = registry.validate_event(raw_event_missing_field)
        assert len(errors) == 1
        assert "Missing required field 'response'" in errors[0]

    def test_null_raw_data_with_required_fields(
        self,
        registry: SchemaRegistry,
        aws_schema: EventTypeSchema,
    ) -> None:
        event = RawEventData(
            source="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
            event_type="iam_credential_report",
            raw_data=None,  # type: ignore[arg-type]
        )
        registry.register(aws_schema)
        errors = registry.validate_event(event)
        assert len(errors) == 1
        assert "raw_data is None" in errors[0]

    def test_no_required_fields_always_passes(self, registry: SchemaRegistry) -> None:
        schema = EventTypeSchema(
            source="gcp",
            provider="gcp",
            event_type="compute_instances",
            description="GCP instances",
            required_fields=[],
        )
        registry.register(schema)
        event = RawEventData(
            source="gcp",
            source_type=SourceType.CLOUD,
            provider="gcp",
            event_type="compute_instances",
            raw_data={"anything": True},
        )
        assert registry.validate_event(event) == []


# ---------------------------------------------------------------------------
# unhandled_event_types
# ---------------------------------------------------------------------------


class TestUnhandledEventTypes:
    def test_unhandled_returns_gaps(self, registry: SchemaRegistry) -> None:
        """Register an event_type for a source that no normalizer handles.

        Uses an empty NormalizerRegistry to avoid the GenericNormalizer
        catch-all that may be registered in the singleton during full
        test-suite runs.
        """
        from unittest.mock import patch

        from warlock.normalizers.base import NormalizerRegistry

        schema = EventTypeSchema(
            source="totally_fake_source",
            provider="totally_fake_source",
            event_type="fake_check",
            description="Should have no normalizer",
        )
        registry.register(schema)

        empty_normalizer_registry = NormalizerRegistry()
        with patch(
            "warlock.normalizers.base.registry",
            empty_normalizer_registry,
        ):
            unhandled = registry.unhandled_event_types()
        assert ("totally_fake_source", "fake_check") in unhandled


# ---------------------------------------------------------------------------
# Auto-discovery helpers
# ---------------------------------------------------------------------------


class TestExtractEventTypes:
    def test_checks_pattern(self) -> None:
        """Simulates the AWS_CHECKS dict pattern."""

        class FakeModule:
            AWS_CHECKS = {
                "iam": [
                    ("get_credential_report", "iam_credential_report"),
                    ("list_users", "iam_users"),
                ],
                "ec2": [
                    ("describe_security_groups", "ec2_security_groups"),
                ],
            }

        results = _extract_event_types_from_module(FakeModule)
        event_types = [et for _, et, _ in results]
        assert "iam_credential_report" in event_types
        assert "iam_users" in event_types
        assert "ec2_security_groups" in event_types

    def test_endpoints_pattern(self) -> None:
        """Simulates the *_ENDPOINTS list pattern."""

        class FakeModule:
            SPLUNK_ENDPOINTS = [
                ("/services/search/jobs", "splunk_notable_events", {}),
                ("/services/saved/searches", "splunk_saved_searches", {}),
            ]

        results = _extract_event_types_from_module(FakeModule)
        event_types = [et for _, et, _ in results]
        assert "splunk_notable_events" in event_types
        assert "splunk_saved_searches" in event_types

    def test_ignores_non_matching_attrs(self) -> None:
        class FakeModule:
            SOMETHING_ELSE = {"a": "b"}
            random_list = [1, 2, 3]

        results = _extract_event_types_from_module(FakeModule)
        assert results == []


class TestGuessProvider:
    def test_simple(self) -> None:
        assert _guess_provider_from_module("warlock.connectors.aws") == "aws"

    def test_compound(self) -> None:
        assert _guess_provider_from_module("warlock.connectors.cisco_umbrella") == "cisco_umbrella"


# ---------------------------------------------------------------------------
# build_registry_from_connectors (integration)
# ---------------------------------------------------------------------------


class TestBuildRegistryFromConnectors:
    def test_discovers_aws_checks(self) -> None:
        """The real AWS connector has AWS_CHECKS — verify they are discovered."""
        reg = build_registry_from_connectors()
        schema = reg.get_schema("aws", "iam_credential_report")
        assert schema is not None
        assert schema.event_type == "iam_credential_report"

    def test_discovers_nonzero_schemas(self) -> None:
        reg = build_registry_from_connectors()
        # We know there are many connectors with CHECKS/ENDPOINTS
        assert reg.count > 0
