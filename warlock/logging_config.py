"""Logging configuration with optional JSON output and correlation IDs.

Supports structured JSON logging when ``WLK_LOG_FORMAT=json``.  The JSON
formatter emits one JSON object per line with fields suitable for log
aggregation pipelines (Datadog, ELK, CloudWatch, etc.).
"""

import json as _json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

from warlock.config import get_settings

# Correlation ID for request tracing across pipeline stages
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

# Optional per-request context vars for structured logging
tenant_id: ContextVar[str] = ContextVar("tenant_id", default="")
user_id: ContextVar[str] = ContextVar("user_id", default="")


class CorrelationFilter(logging.Filter):
    """Inject correlation_id, tenant_id, user_id into every log record."""

    def filter(self, record):
        record.correlation_id = correlation_id.get("")
        record.tenant_id = tenant_id.get("")
        record.user_id = user_id.get("")
        return True


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging pipelines.

    Outputs one JSON object per line with:
    - timestamp (ISO-8601 UTC)
    - level
    - logger
    - message
    - correlation_id
    - tenant_id
    - user_id
    - exception (only when present)
    """

    def format(self, record):
        log_data: dict[str, str] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", ""),
            "tenant_id": getattr(record, "tenant_id", ""),
            "user_id": getattr(record, "user_id", ""),
        }
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = self.formatException(record.exc_info)
        return _json.dumps(log_data)


def configure_logging(json_mode: bool = False) -> None:
    """Configure root logger based on WLK_LOG_LEVEL and WLK_LOG_FORMAT.

    Parameters
    ----------
    json_mode:
        Force JSON output regardless of config.  When *False* (default),
        the ``WLK_LOG_FORMAT`` setting is consulted instead.
    """
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    use_json = json_mode or settings.log_format.lower() == "json"
    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s [%(correlation_id)s] %(name)s — %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    # Add correlation filter
    handler.addFilter(CorrelationFilter())
    root.addHandler(handler)


def new_correlation_id() -> str:
    """Generate and set a new correlation ID for the current context."""
    cid = str(uuid.uuid4())[:8]
    correlation_id.set(cid)
    return cid
