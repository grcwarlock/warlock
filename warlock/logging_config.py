"""Logging configuration with optional JSON output and correlation IDs."""

import logging
import sys
import uuid
from contextvars import ContextVar

from warlock.config import get_settings

# Correlation ID for request tracing across pipeline stages
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


class CorrelationFilter(logging.Filter):
    """Inject correlation_id into every log record."""

    def filter(self, record):
        record.correlation_id = correlation_id.get("")
        return True


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging pipelines."""

    def format(self, record):
        import json
        from datetime import datetime, timezone

        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", ""),
        }
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def configure_logging():
    """Configure root logger based on WLK_LOG_LEVEL and WLK_LOG_FORMAT."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if settings.log_format.lower() == "json":
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
