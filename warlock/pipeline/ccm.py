"""Continuous Control Monitoring (CCM) engine.

Watches for evidence changes and triggers targeted reassessment of affected
controls without running the full pipeline. Uses the EventBus for event-driven
triggers and the existing Assessor for evaluation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from warlock.assessors.engine import Assessor
    from warlock.mappers.control_mapper import ControlMapper
    from warlock.pipeline.bus import EventBus, PipelineEvent

log = logging.getLogger(__name__)


class ContinuousControlMonitor:
    """Monitors for evidence changes and triggers targeted reassessment."""

    def __init__(self, assessor: Assessor, mapper: ControlMapper, bus: EventBus) -> None:
        self.assessor = assessor
        self.mapper = mapper
        self.bus = bus
        # (framework, control_id) -> set of event_types that affect it
        self._control_evidence_map: dict[tuple[str, str], set[str]] = defaultdict(set)

    # ------------------------------------------------------------------
    # Map construction
    # ------------------------------------------------------------------

    def build_control_evidence_map(self, session: Any) -> None:  # noqa: ARG002
        """Build a map of which event_types affect which controls.

        Uses the ControlMapper's explicit rules (loaded from framework YAML
        check definitions) to determine dependencies.  Each explicit rule
        records a (source, event_type) -> (framework, control_id) mapping;
        we invert that here so we can quickly look up affected controls when
        a finding arrives.

        The ``session`` parameter is accepted for API symmetry (callers may
        pass a DB session expecting future persistence of the map), but the
        current implementation derives everything from the in-memory mapper
        rules so no DB queries are needed.
        """
        self._control_evidence_map.clear()
        for rule in self.mapper._explicit_rules:
            key = (rule.framework, rule.control_id)
            self._control_evidence_map[key].add(rule.event_type)
        log.info(
            "CCM: built control-evidence map for %d control entries",
            len(self._control_evidence_map),
        )

    # ------------------------------------------------------------------
    # Event-driven reassessment
    # ------------------------------------------------------------------

    def on_finding_created(self, event: PipelineEvent) -> None:
        """Called when a new finding is created.

        Receives a ``finding.normalized`` PipelineEvent whose ``metadata``
        contains the serialised FindingData fields.  Determines which controls
        are affected by the finding's observation_type and triggers targeted
        reassessment for just those controls.
        """
        from warlock.db.engine import get_session

        metadata = event.metadata or {}
        observation_type: str = metadata.get("observation_type", "")
        framework: str | None = metadata.get("framework")

        if not observation_type:
            log.debug("CCM: on_finding_created skipped — no observation_type in event metadata")
            return

        # Collect affected (framework, control_id) pairs
        affected: list[tuple[str, str]] = []
        for (fw, ctrl_id), event_types in self._control_evidence_map.items():
            if framework and fw != framework:
                continue
            if observation_type in event_types or "*" in event_types:
                affected.append((fw, ctrl_id))

        if not affected:
            log.debug("CCM: no controls mapped to observation_type=%s", observation_type)
            return

        log.info(
            "CCM: finding.normalized(%s) affects %d control(s) — triggering reassessment",
            observation_type,
            len(affected),
        )

        # Group by framework for reassess_controls
        by_framework: dict[str, list[str]] = defaultdict(list)
        for fw, ctrl_id in affected:
            by_framework[fw].append(ctrl_id)

        with get_session() as session:
            for fw, ctrl_ids in by_framework.items():
                self.reassess_controls(session, fw, ctrl_ids, event)

    def reassess_controls(
        self,
        session: Any,
        framework: str,
        control_ids: list[str],
        finding_event: PipelineEvent,
    ) -> list[Any]:
        """Re-assess specific controls using the existing Assessor.

        Constructs a minimal MappedFinding from the pipeline event's metadata
        and the requested (framework, control_id) pairs, then delegates to
        ``Assessor.assess``.  Each result is persisted as a new ControlResult
        row and a ``control.assessed`` event is published on the bus.

        Returns the list of ControlResultData objects produced.
        """
        from warlock.assessors.engine import ControlResultData
        from warlock.db.models import ControlResult
        from warlock.mappers.control_mapper import ControlMappingData, MappedFinding
        from warlock.normalizers.base import FindingData
        from warlock.pipeline.bus import PipelineEvent as BusEvent

        metadata = finding_event.metadata or {}

        # Reconstruct a FindingData stub from the event metadata
        finding = FindingData(
            id=metadata.get("finding_id", finding_event.payload_id),
            source=metadata.get("source", "ccm"),
            observation_type=metadata.get("observation_type", ""),
            severity=metadata.get("severity", "info"),
            title=metadata.get("title", "CCM reassessment"),
            raw_event_id=metadata.get("raw_event_id", finding_event.payload_id),
            detail=metadata.get("detail", {}),
            resource_type=metadata.get("resource_type", ""),
            resource_id=metadata.get("resource_id", ""),
        )

        # Build minimal mappings for only the requested controls
        freq_map = self.mapper._monitoring_frequencies
        mappings = [
            ControlMappingData(
                finding_id=finding.id,
                framework=framework,
                control_id=ctrl_id,
                mapping_method="ccm_targeted",
                confidence=1.0,
                monitoring_frequency=freq_map.get((framework, ctrl_id), "monthly"),
            )
            for ctrl_id in control_ids
        ]

        mapped = MappedFinding(finding=finding, mappings=mappings)
        results: list[ControlResultData] = self.assessor.assess(mapped)

        persisted = 0
        for result in results:
            try:
                row = ControlResult(
                    id=result.id,
                    finding_id=result.finding_id,
                    control_mapping_id=result.control_mapping_id,
                    framework=result.framework,
                    control_id=result.control_id,
                    status=result.status,
                    severity=result.severity,
                    assertion_name=result.assertion_name,
                    assertion_passed=result.assertion_passed,
                    assertion_findings=result.assertion_findings,
                    ai_assessment=result.ai_assessment,
                    ai_confidence=result.ai_confidence,
                    ai_model=result.ai_model,
                    remediation_summary=result.remediation_summary,
                    remediation_steps=result.remediation_steps,
                    console_path=result.console_path,
                    evidence_ids=result.evidence_ids,
                    assessed_at=result.assessed_at,
                    assessor=result.assessor,
                )
                session.add(row)
                persisted += 1

                self.bus.publish(
                    BusEvent(
                        event_type="control.assessed",
                        payload_id=result.id,
                        metadata={
                            "framework": result.framework,
                            "control_id": result.control_id,
                            "status": result.status,
                            "trigger": "ccm",
                        },
                    )
                )
            except Exception:
                log.exception(
                    "CCM: failed to persist result for %s/%s",
                    result.framework,
                    result.control_id,
                )

        try:
            session.commit()
        except Exception:
            log.exception("CCM: commit failed after reassessing %s controls", len(control_ids))
            session.rollback()

        log.info(
            "CCM: reassessed %d control(s) in framework=%s, persisted %d result(s)",
            len(control_ids),
            framework,
            persisted,
        )
        return results

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_event_handlers(self) -> None:
        """Register with the EventBus to receive finding.normalized events."""
        self.bus.subscribe("finding.normalized", self.on_finding_created)
        log.info("CCM: subscribed to finding.normalized events")

    # ------------------------------------------------------------------
    # Stale control detection
    # ------------------------------------------------------------------

    def check_stale_controls(self, session: Any, max_age_hours: int = 24) -> list[dict[str, Any]]:
        """Find controls that haven't been assessed within their monitoring_frequency.

        Queries the most recent ControlResult per (framework, control_id) and
        compares its ``assessed_at`` timestamp against both ``max_age_hours``
        and the control's configured ``monitoring_frequency``.  Controls that
        exceed either threshold are returned as a list of dicts suitable for
        logging or downstream remediation workflows.

        Args:
            session: SQLAlchemy session.
            max_age_hours: Fallback maximum age in hours when the control's
                monitoring_frequency cannot be resolved to a duration.

        Returns:
            List of dicts with keys: framework, control_id, last_assessed_at,
            age_hours, monitoring_frequency, threshold_hours.
        """
        from sqlalchemy import text

        # Frequency label → hours
        _FREQ_HOURS: dict[str, int] = {
            "hourly": 1,
            "daily": 24,
            "weekly": 168,
            "monthly": 720,
            "quarterly": 2160,
            "annual": 8760,
        }

        # Pull the most-recent assessed_at per (framework, control_id)
        sql = text(
            """
            SELECT framework, control_id, MAX(assessed_at) AS last_assessed_at
            FROM control_results
            GROUP BY framework, control_id
            """
        )
        try:
            rows = session.execute(sql).fetchall()
        except Exception:
            log.exception("CCM: failed to query control_results for stale check")
            return []

        now = datetime.now(timezone.utc)
        stale: list[dict[str, Any]] = []

        for row in rows:
            framework = row[0]
            control_id = row[1]
            raw_ts = row[2]

            # Normalise to aware datetime
            if raw_ts is None:
                continue
            if isinstance(raw_ts, str):
                try:
                    last_assessed = datetime.fromisoformat(raw_ts)
                except ValueError:
                    continue
            else:
                last_assessed = raw_ts

            if last_assessed.tzinfo is None:
                last_assessed = last_assessed.replace(tzinfo=timezone.utc)

            age_hours = (now - last_assessed).total_seconds() / 3600.0

            freq = self.mapper._monitoring_frequencies.get((framework, control_id), "")
            threshold_hours = _FREQ_HOURS.get(freq, max_age_hours)

            if age_hours > threshold_hours:
                stale.append(
                    {
                        "framework": framework,
                        "control_id": control_id,
                        "last_assessed_at": last_assessed.isoformat(),
                        "age_hours": round(age_hours, 2),
                        "monitoring_frequency": freq or "unknown",
                        "threshold_hours": threshold_hours,
                    }
                )

        if stale:
            log.warning(
                "CCM: %d stale control(s) detected (threshold %dh)",
                len(stale),
                max_age_hours,
            )
        else:
            log.info("CCM: all controls assessed within their monitoring frequency")

        return stale
