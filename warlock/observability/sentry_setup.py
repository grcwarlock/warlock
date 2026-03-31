"""Sentry error tracking (optional).

Initialises the Sentry SDK when ``WLK_SENTRY_DSN`` is set and the
``sentry-sdk`` package is installed.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_HAS_SENTRY = False
try:
    import sentry_sdk

    _HAS_SENTRY = True
except ImportError:
    pass


def setup_sentry() -> None:
    """Initialise Sentry if configured.  No-op otherwise."""
    from warlock.config import get_settings

    settings = get_settings()
    dsn = getattr(settings, "sentry_dsn", "")
    if not dsn or not _HAS_SENTRY:
        log.debug("Sentry not configured or sentry-sdk not installed")
        return

    sentry_sdk.init(
        dsn=dsn,
        environment=settings.env,
        traces_sample_rate=0.1,
    )
    log.info("Sentry error tracking enabled (env=%s)", settings.env)
