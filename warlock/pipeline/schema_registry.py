"""Event-type schema registry (OPS-7).

Central registry of all event_type strings produced by connectors. Enables
startup-time validation that every connector event_type has a matching
normalizer, and runtime validation that raw events conform to their schema.

Usage::

    from warlock.pipeline.schema_registry import SchemaRegistry, EventTypeSchema

    reg = SchemaRegistry()
    reg.register(EventTypeSchema(
        source="aws",
        provider="aws",
        event_type="iam_credential_report",
        description="IAM credential report for all users",
        required_fields=["response"],
        normalizer_class="AWSNormalizer",
    ))

    errors = reg.validate_event(some_raw_event)
    if errors:
        log.warning("Schema validation errors: %s", errors)
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from dataclasses import dataclass, field
from typing import Any

from warlock.connectors.base import RawEventData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventTypeSchema:
    """Defines a registered event type produced by a connector."""

    source: str  # e.g. "aws"
    provider: str  # e.g. "aws_iam" or "aws"
    event_type: str  # e.g. "iam_credential_report"
    description: str  # brief human-readable description
    required_fields: list[str] = field(default_factory=list)  # keys expected in raw_data
    normalizer_class: str | None = None  # which normalizer handles it (documentation)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class SchemaRegistry:
    """Central registry of connector event-type schemas.

    Thread-safe for reads after initial registration (registration is
    expected to happen once at startup).
    """

    def __init__(self) -> None:
        # Key: (source, event_type) → schema
        self._schemas: dict[tuple[str, str], EventTypeSchema] = {}

    def register(self, schema: EventTypeSchema) -> None:
        """Register an event type schema.

        If the same (source, event_type) is registered twice, the later
        registration wins and a debug message is logged.
        """
        key = (schema.source, schema.event_type)
        if key in self._schemas:
            log.debug(
                "Overwriting schema for (%s, %s)",
                schema.source,
                schema.event_type,
            )
        self._schemas[key] = schema

    def get_schema(self, source: str, event_type: str) -> EventTypeSchema | None:
        """Look up a schema by source and event_type."""
        return self._schemas.get((source, event_type))

    def list_schemas(self, source: str | None = None) -> list[EventTypeSchema]:
        """List all registered schemas, optionally filtered by source."""
        if source is None:
            return list(self._schemas.values())
        return [s for s in self._schemas.values() if s.source == source]

    def validate_event(self, raw_event: RawEventData) -> list[str]:
        """Validate a raw event against the registry.

        Returns a list of validation error strings. An empty list means the
        event is valid. Checks performed:

        1. The event_type is registered for this source.
        2. All required_fields are present in raw_data.
        """
        errors: list[str] = []
        schema = self.get_schema(raw_event.source, raw_event.event_type)

        if schema is None:
            errors.append(
                f"Unregistered event_type '{raw_event.event_type}' for source '{raw_event.source}'"
            )
            return errors

        # Check required fields in raw_data
        if raw_event.raw_data is not None:
            for req_field in schema.required_fields:
                if req_field not in raw_event.raw_data:
                    errors.append(
                        f"Missing required field '{req_field}' in raw_data "
                        f"for event_type '{raw_event.event_type}'"
                    )
        elif schema.required_fields:
            errors.append(
                f"raw_data is None but event_type '{raw_event.event_type}' "
                f"requires fields: {schema.required_fields}"
            )

        return errors

    def unhandled_event_types(self) -> list[tuple[str, str]]:
        """Cross-reference with normalizer registry to find gaps.

        Returns a list of (source, event_type) tuples that have no matching
        normalizer registered in the NormalizerRegistry singleton.
        """
        from warlock.normalizers.base import registry as normalizer_registry

        unhandled: list[tuple[str, str]] = []
        for (source, event_type), schema in sorted(self._schemas.items()):
            # Build a lightweight RawEventData to probe can_handle
            probe = RawEventData(
                source=source,
                source_type="custom",  # type: ignore[arg-type]
                provider=schema.provider,
                event_type=event_type,
                raw_data={},
            )
            handled = False
            for normalizer in normalizer_registry.list_normalizers():
                try:
                    if normalizer.can_handle(probe):
                        handled = True
                        break
                except Exception:
                    # Defensive — don't let a broken normalizer crash discovery
                    pass
            if not handled:
                unhandled.append((source, event_type))
        return unhandled

    @property
    def count(self) -> int:
        """Total number of registered event type schemas."""
        return len(self._schemas)


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------


def _extract_event_types_from_module(module: Any) -> list[tuple[str, str, str]]:
    """Extract (source/provider, event_type, variable_name) from a connector module.

    Scans module-level dicts that follow the common connector patterns:
    - AWS_CHECKS: dict[str, list[tuple[str, str]]]  (service -> [(method, event_type)])
    - *_ENDPOINTS: list[tuple[str, str, ...]]  (endpoint, event_type, ...)
    - Inline event_type= assignments are not captured here (they require AST
      parsing which is overkill for startup validation).
    """
    results: list[tuple[str, str, str]] = []

    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if obj is None:
            continue

        # Pattern 1: AWS_CHECKS style — dict mapping service names to
        # list of tuples where the last element is the event_type string.
        if attr_name.endswith("_CHECKS") or attr_name == "CHECKS":
            if isinstance(obj, dict):
                for _service, checks in obj.items():
                    if isinstance(checks, list):
                        for item in checks:
                            if isinstance(item, (list, tuple)) and len(item) >= 2:
                                event_type = item[-1]
                                if isinstance(event_type, str):
                                    results.append(("", event_type, attr_name))

        # Pattern 2: *_ENDPOINTS style — list of tuples where position 1
        # is the event_type string.
        elif attr_name.endswith("_ENDPOINTS") or attr_name == "ENDPOINTS":
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        event_type = item[1]
                        if isinstance(event_type, str):
                            results.append(("", event_type, attr_name))

    return results


def _guess_provider_from_module(module_name: str) -> str:
    """Derive the provider/source name from the module path.

    ``warlock.connectors.aws`` -> ``"aws"``
    ``warlock.connectors.cisco_umbrella`` -> ``"cisco_umbrella"``
    """
    parts = module_name.rsplit(".", 1)
    return parts[-1] if parts else module_name


def build_registry_from_connectors() -> SchemaRegistry:
    """Scan all connector modules and auto-register discovered event types.

    This is intended for startup validation. After building the registry,
    callers should inspect ``unhandled_event_types()`` and log warnings.

    Returns the populated SchemaRegistry.
    """
    import warlock.connectors as connectors_pkg

    reg = SchemaRegistry()
    pkg_path = connectors_pkg.__path__
    prefix = connectors_pkg.__name__ + "."

    for importer, modname, ispkg in pkgutil.iter_modules(pkg_path, prefix):
        if modname.endswith(".base"):
            continue  # skip the base module

        try:
            module = importlib.import_module(modname)
        except Exception:
            log.debug("Could not import connector module %s", modname, exc_info=True)
            continue

        provider = _guess_provider_from_module(modname)
        extracted = _extract_event_types_from_module(module)

        for _source_hint, event_type, var_name in extracted:
            schema = EventTypeSchema(
                source=provider,
                provider=provider,
                event_type=event_type,
                description=f"Auto-discovered from {modname}.{var_name}",
            )
            reg.register(schema)

    discovered = reg.count
    log.info("Schema registry: %d event types discovered from connectors", discovered)

    # Cross-reference with normalizer registry
    unhandled = reg.unhandled_event_types()
    if unhandled:
        log.warning(
            "Schema registry: %d event types have no matching normalizer: %s",
            len(unhandled),
            ", ".join(f"{s}:{et}" for s, et in unhandled),
        )

    return reg


# ---------------------------------------------------------------------------
# Module-level singleton (lazy)
# ---------------------------------------------------------------------------

_registry: SchemaRegistry | None = None


def get_schema_registry() -> SchemaRegistry:
    """Return the module-level schema registry singleton.

    On first call, builds the registry by scanning connector modules.
    Subsequent calls return the cached instance.
    """
    global _registry
    if _registry is None:
        _registry = build_registry_from_connectors()
    return _registry
