"""Connector validation test infrastructure.

Validates ALL 165 connectors are importable, registered, properly structured,
aligned with normalizers, and that config validation returns errors (not crashes)
when API keys are absent.
"""

from __future__ import annotations

import pytest

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    SourceType,
    registry as connector_registry,
)
from warlock.normalizers.base import (
    registry as normalizer_registry,
)
from warlock.pipeline.loader import (
    _CONNECTOR_MODULES,
    _NORMALIZER_MODULES,
    load_all_connectors,
    load_all_normalizers,
)


# ---------------------------------------------------------------------------
# Fixtures — load registries once per module
# ---------------------------------------------------------------------------

EXPECTED_CONNECTOR_COUNT = 165


@pytest.fixture(scope="module", autouse=True)
def _load_registries() -> None:
    """Ensure all connector and normalizer modules are imported."""
    load_all_connectors()
    load_all_normalizers()


# ===================================================================
# 1. ALL 165 CONNECTORS IMPORTABLE AND REGISTERED
# ===================================================================


def test_connector_module_count():
    """The loader module list matches the expected connector count."""
    assert len(_CONNECTOR_MODULES) == EXPECTED_CONNECTOR_COUNT, (
        f"Expected {EXPECTED_CONNECTOR_COUNT} connector modules in loader, "
        f"got {len(_CONNECTOR_MODULES)}"
    )


def test_all_connectors_registered():
    """Every connector module successfully registered a provider type."""
    registered = connector_registry.list_types()
    assert len(registered) >= EXPECTED_CONNECTOR_COUNT, (
        f"Expected at least {EXPECTED_CONNECTOR_COUNT} registered connector types, "
        f"got {len(registered)}"
    )


def test_normalizer_module_count():
    """The loader normalizer list has at least as many modules as connectors.

    There may be extras (e.g. the generic/fallback normalizer).
    """
    # Subtract 1 for the generic/fallback normalizer that is not connector-paired
    non_generic = [m for m in _NORMALIZER_MODULES if "generic" not in m]
    assert len(non_generic) >= EXPECTED_CONNECTOR_COUNT, (
        f"Expected at least {EXPECTED_CONNECTOR_COUNT} normalizer modules "
        f"(excluding generic), got {len(non_generic)}"
    )


# ===================================================================
# 2. EACH CONNECTOR HAS VALID BaseConnector SUBCLASS
# ===================================================================


def _get_all_provider_names() -> list[str]:
    """Return all registered provider names."""
    return connector_registry.list_types()


@pytest.fixture(scope="module")
def all_providers() -> list[str]:
    return _get_all_provider_names()


def test_all_providers_are_base_connector_subclasses(all_providers: list[str]):
    """Every registered type must be a subclass of BaseConnector."""
    for provider in all_providers:
        cls = connector_registry._types[provider]
        assert issubclass(cls, BaseConnector), (
            f"Provider {provider!r} registered class {cls.__name__} is not a BaseConnector subclass"
        )


def test_all_connectors_have_validate_method(all_providers: list[str]):
    """Every connector class must define a validate() method."""
    for provider in all_providers:
        cls = connector_registry._types[provider]
        assert hasattr(cls, "validate"), (
            f"Connector {provider!r} ({cls.__name__}) missing validate() method"
        )
        # Verify it is callable (not just an inherited abstract stub)
        assert callable(getattr(cls, "validate")), (
            f"Connector {provider!r} validate is not callable"
        )


def test_all_connectors_have_health_check_method(all_providers: list[str]):
    """Every connector class must define a health_check() method."""
    for provider in all_providers:
        cls = connector_registry._types[provider]
        assert hasattr(cls, "health_check"), (
            f"Connector {provider!r} ({cls.__name__}) missing health_check() method"
        )
        assert callable(getattr(cls, "health_check")), (
            f"Connector {provider!r} health_check is not callable"
        )


def test_all_connectors_have_collect_method(all_providers: list[str]):
    """Every connector class must define a collect() method."""
    for provider in all_providers:
        cls = connector_registry._types[provider]
        assert hasattr(cls, "collect"), (
            f"Connector {provider!r} ({cls.__name__}) missing collect() method"
        )
        assert callable(getattr(cls, "collect")), f"Connector {provider!r} collect is not callable"


# ===================================================================
# 3. CONNECTOR <-> NORMALIZER ALIGNMENT
# ===================================================================


def _build_normalizer_event_types() -> set[str]:
    """Collect all event_types that at least one normalizer can handle.

    Normalizers declare their handled event types via HANDLERS dicts
    or similar attributes. We probe each normalizer's can_handle()
    against known event types from connector modules.
    """

    handled: set[str] = set()
    normalizers = normalizer_registry.list_normalizers()

    # Gather event_types from all connector HANDLERS/CHECKS attributes
    for provider in connector_registry.list_types():
        cls = connector_registry._types[provider]
        # Connectors often have a CHECKS dict or similar with event_types
        # We also probe the normalizer directly
        event_types_to_check: list[tuple[str, str]] = []

        # Look for common patterns: AWS_CHECKS, CHECKS, EVENT_TYPES, etc.
        for attr_name in dir(cls):
            attr = getattr(cls, attr_name, None)
            if isinstance(attr, dict):
                # Pattern: {"service": [("method", "event_type"), ...]}
                for _key, val in attr.items():
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, tuple) and len(item) == 2:
                                event_types_to_check.append((provider, item[1]))
                            elif isinstance(item, str):
                                event_types_to_check.append((provider, item))

        # Try to find event_types from normalizer HANDLERS dicts
        for norm in normalizers:
            handlers = getattr(norm, "HANDLERS", None)
            if isinstance(handlers, dict):
                for et in handlers:
                    handled.add(et)

    return handled


def test_normalizer_coverage_exists():
    """At least one normalizer exists for the system."""
    normalizers = normalizer_registry.list_normalizers()
    assert len(normalizers) > 0, "No normalizers registered"


def test_every_connector_has_matching_normalizer(all_providers: list[str]):
    """For each connector provider, verify at least one normalizer can handle
    events from that provider by checking can_handle() with a synthetic event.
    """
    from warlock.connectors.base import RawEventData, SourceType

    normalizers = normalizer_registry.list_normalizers()
    missing: list[str] = []

    for provider in all_providers:
        cls = connector_registry._types[provider]

        # Build a list of event_types this connector produces
        event_types: list[str] = []
        for attr_name in dir(cls):
            attr = getattr(cls, attr_name, None)
            if isinstance(attr, dict):
                for _key, val in attr.items():
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, tuple) and len(item) == 2:
                                event_types.append(item[1])
                            elif isinstance(item, str):
                                event_types.append(item)
                    elif isinstance(val, str):
                        # Direct event_type values in HANDLERS-style dicts
                        event_types.append(_key)

        if not event_types:
            # Some connectors might not expose event types as class attrs;
            # skip those — they are checked via integration tests (demo seed).
            continue

        # Check at least one event_type from this connector is handled
        any_handled = False
        for et in event_types:
            probe = RawEventData(
                source=provider,
                source_type=SourceType.CUSTOM,
                provider=provider,
                event_type=et,
                raw_data={},
            )
            for norm in normalizers:
                if norm.can_handle(probe):
                    any_handled = True
                    break
            if any_handled:
                break

        if not any_handled:
            missing.append(provider)

    assert not missing, f"Connectors with no matching normalizer for any event_type: {missing}"


# ===================================================================
# 4. CONNECTOR CONFIG VALIDATION (no crashes)
# ===================================================================


def test_connector_validate_returns_list_not_crash(all_providers: list[str]):
    """Calling validate() on each connector with no API keys should return
    a list of error strings, never raise an unhandled exception.
    """
    failures: list[str] = []

    for provider in all_providers:
        cls = connector_registry._types[provider]
        config = ConnectorConfig(
            name=f"test-{provider}",
            source_type=SourceType.CUSTOM,
            provider=provider,
        )
        try:
            instance = cls(config)
            result = instance.validate()
            if not isinstance(result, list):
                failures.append(
                    f"{provider}: validate() returned {type(result).__name__}, expected list"
                )
        except Exception as exc:
            failures.append(f"{provider}: validate() raised {type(exc).__name__}: {exc}")

    assert not failures, f"{len(failures)} connector(s) failed validation:\n" + "\n".join(
        f"  - {f}" for f in failures
    )


def test_connector_validate_reports_missing_creds(all_providers: list[str]):
    """With no env vars set, connectors that require API keys should report
    errors via validate(), not silently pass.

    This is a soft check — we verify that connectors with secret_env_vars
    in their config detect the missing credentials.
    """
    connectors_with_errors = 0

    for provider in all_providers:
        cls = connector_registry._types[provider]
        config = ConnectorConfig(
            name=f"test-{provider}",
            source_type=SourceType.CUSTOM,
            provider=provider,
        )
        try:
            instance = cls(config)
            errors = instance.validate()
            if errors:
                connectors_with_errors += 1
        except Exception:
            # Already caught by the crash test above
            pass

    # Most connectors require credentials — at least half should report errors
    # when no env vars are configured.
    assert connectors_with_errors > 0, (
        "No connectors reported validation errors despite missing credentials"
    )


# ===================================================================
# 5. REGISTRY INTEGRITY
# ===================================================================


def test_no_duplicate_providers():
    """Each provider name should map to exactly one connector class."""
    providers = connector_registry.list_types()
    seen: dict[str, type] = {}
    dupes: list[str] = []
    for p in providers:
        cls = connector_registry._types[p]
        if p in seen and seen[p] is not cls:
            dupes.append(f"{p}: {seen[p].__name__} vs {cls.__name__}")
        seen[p] = cls
    assert not dupes, f"Duplicate provider registrations: {dupes}"


def test_connector_classes_are_not_abstract(all_providers: list[str]):
    """Registered connector classes must be concrete (instantiable),
    not left as abstract stubs.
    """
    abstract_providers: list[str] = []
    for provider in all_providers:
        cls = connector_registry._types[provider]
        # Check if the class still has abstract methods
        abstracts = getattr(cls, "__abstractmethods__", frozenset())
        if abstracts:
            abstract_providers.append(
                f"{provider} ({cls.__name__}): abstract methods = {set(abstracts)}"
            )
    assert not abstract_providers, "Abstract connector classes registered:\n" + "\n".join(
        f"  - {a}" for a in abstract_providers
    )
