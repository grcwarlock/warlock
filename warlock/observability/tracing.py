"""OpenTelemetry distributed tracing (optional).

Instruments FastAPI and SQLAlchemy when the ``opentelemetry`` packages are
installed.  Falls back silently when they are absent — no new hard
dependency.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI
    from sqlalchemy import Engine

log = logging.getLogger(__name__)

# -- Optional dependency probe ------------------------------------------------

_HAS_OTEL = False
try:
    from opentelemetry import trace  # noqa: F401
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.instrumentation.fastapi import (
        FastAPIInstrumentor,
    )
    from opentelemetry.instrumentation.sqlalchemy import (
        SQLAlchemyInstrumentor,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _HAS_OTEL = True
except ImportError:
    pass


def setup_tracing(
    app: FastAPI,
    engine: Engine,
    service_name: str = "warlock-api",
    endpoint: str = "",
) -> None:
    """Configure OpenTelemetry tracing for FastAPI and SQLAlchemy.

    Does nothing when the ``opentelemetry`` packages are not installed.

    Parameters
    ----------
    app:
        The FastAPI application to instrument.
    engine:
        The SQLAlchemy engine to instrument.
    service_name:
        Logical service name reported to the collector.
    endpoint:
        OTLP gRPC endpoint (e.g. ``http://localhost:4317``).  When empty
        the default OTEL_EXPORTER_OTLP_ENDPOINT env var is used.
    """
    if not _HAS_OTEL:
        log.debug("opentelemetry packages not installed — distributed tracing disabled")
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    exporter_kwargs: dict[str, str] = {}
    if endpoint:
        exporter_kwargs["endpoint"] = endpoint
    exporter = OTLPSpanExporter(**exporter_kwargs)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)
    SQLAlchemyInstrumentor().instrument(engine=engine)

    log.info("OpenTelemetry tracing enabled (service=%s)", service_name)
