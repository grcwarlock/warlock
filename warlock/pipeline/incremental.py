"""ARCH-003: Incremental pipeline mode with high-water mark tracking.

Tracks the last-processed cursor (timestamp or offset) per connector so
that subsequent pipeline runs can skip already-ingested data.  Marks are
stored in the ``ConnectorRun.errors`` JSON field under the key
``_high_water_mark`` (reusing the existing JSON column to avoid a schema
migration).

Usage::

    from warlock.pipeline.incremental import IncrementalTracker
    from warlock.db.engine import get_session

    with get_session() as session:
        tracker = IncrementalTracker(session)
        if tracker.should_collect("aws_guardduty"):
            mark = tracker.get_high_water_mark("aws_guardduty")
            # ... collect events newer than *mark* ...
            tracker.set_high_water_mark("aws_guardduty", new_mark)

Configure via ``WLK_PIPELINE_MODE`` (``full`` | ``incremental``).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


class IncrementalTracker:
    """Track high-water marks per connector for change detection."""

    # Key used inside the ConnectorRun JSON metadata to store the mark.
    _HWM_KEY = "_high_water_mark"

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_high_water_mark(self, connector_name: str) -> str | None:
        """Return the last processed timestamp/cursor for *connector_name*.

        Scans the most recent *successful* ``ConnectorRun`` for this
        connector and extracts the stored mark from its JSON metadata.
        Returns ``None`` if no mark has been recorded.
        """
        from warlock.db.models import ConnectorRun

        row = (
            self.session.query(ConnectorRun)
            .filter(
                ConnectorRun.connector_name == connector_name,
                ConnectorRun.status.in_(("success", "partial")),
            )
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )
        if row is None:
            return None

        # The mark is stashed in the errors JSON column under _HWM_KEY.
        meta = row.errors if isinstance(row.errors, dict) else {}
        if isinstance(row.errors, str):
            try:
                meta = json.loads(row.errors)
            except (json.JSONDecodeError, TypeError):
                meta = {}
        return meta.get(self._HWM_KEY)

    def set_high_water_mark(self, connector_name: str, marker: str) -> None:
        """Persist *marker* as the high-water mark for *connector_name*.

        Updates the most recent ``ConnectorRun`` for this connector. If
        no run exists yet, the mark is silently discarded (it will be
        written on the next successful run).
        """
        from warlock.db.models import ConnectorRun

        row = (
            self.session.query(ConnectorRun)
            .filter(ConnectorRun.connector_name == connector_name)
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )
        if row is None:
            log.warning(
                "No ConnectorRun found for %s — cannot persist high-water mark",
                connector_name,
            )
            return

        # Merge the mark into existing JSON metadata.
        existing: dict = {}
        if isinstance(row.errors, dict):
            existing = dict(row.errors)
        elif isinstance(row.errors, list):
            # Legacy format — wrap to preserve error entries.
            existing = {"_errors": row.errors}
        row.errors = {**existing, self._HWM_KEY: marker}

        log.debug("Set high-water mark for %s = %s", connector_name, marker)

    def should_collect(self, connector_name: str, mode: str | None = None) -> bool:
        """Return ``True`` if *connector_name* should run.

        In ``full`` mode every connector always runs.  In ``incremental``
        mode a connector is skipped only if it has a high-water mark newer
        than *now* (which shouldn't happen — so effectively it always runs,
        but the caller should restrict its query window to events after the
        mark).

        Parameters
        ----------
        connector_name:
            Connector identifier.
        mode:
            Pipeline mode override.  Falls back to
            ``get_settings().pipeline_mode``.
        """
        if mode is None:
            from warlock.config import get_settings

            mode = get_settings().pipeline_mode

        if mode != "incremental":
            return True

        mark = self.get_high_water_mark(connector_name)
        if mark is None:
            # No prior run — must collect.
            return True

        # In incremental mode, always collect but the caller should use
        # the mark to restrict its query window.
        log.debug(
            "Incremental mode: connector %s has mark=%s — will collect delta",
            connector_name,
            mark,
        )
        return True

    def mark_now(self, connector_name: str) -> None:
        """Convenience: set the high-water mark to the current UTC timestamp."""
        self.set_high_water_mark(
            connector_name,
            datetime.now(timezone.utc).isoformat(),
        )
