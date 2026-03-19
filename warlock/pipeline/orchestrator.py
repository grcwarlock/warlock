"""The spine. Wires Stage 1 → 2 → 3 → 4 together via the event bus."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.connectors.base import ConnectorRegistry, ConnectorResult, RawEventData
from warlock.normalizers.base import FindingData, NormalizerRegistry
from warlock.mappers.control_mapper import ControlMapper
from warlock.assessors.engine import Assessor, ControlResultData
from warlock.pipeline.bus import EventBus, PipelineEvent
from warlock.db import models

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline run stats
# ---------------------------------------------------------------------------

@dataclass
class PipelineRunStats:
    run_id: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    raw_events_collected: int = 0
    findings_normalized: int = 0
    controls_mapped: int = 0
    results_assessed: int = 0

    connectors_succeeded: int = 0
    connectors_failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    """Orchestrates the full flow: Ingest → Normalize → Map → Assess.

    Each stage persists its output and publishes an event.
    The event bus allows any consumer to react to any stage's output
    without the pipeline knowing about consumers.
    """

    def __init__(
        self,
        connectors: ConnectorRegistry,
        normalizers: NormalizerRegistry,
        mapper: ControlMapper,
        assessor: Assessor,
        bus: EventBus,
    ) -> None:
        self.connectors = connectors
        self.normalizers = normalizers
        self.mapper = mapper
        self.assessor = assessor
        self.bus = bus

    def run(self, session: Session) -> PipelineRunStats:
        """Execute the full pipeline. One pass, all connectors."""
        stats = PipelineRunStats()
        log.info("Pipeline run starting")

        # Stage 1: Collect raw events from all connectors
        connector_results = self.connectors.collect_all()
        for cr in connector_results:
            if cr.status in ("success", "partial"):
                stats.connectors_succeeded += 1
            else:
                stats.connectors_failed += 1
                stats.errors.extend(cr.errors)

            # Persist connector run
            db_run = self._persist_connector_run(session, cr)

            for raw_event in cr.events:
                # Persist raw event
                db_raw = self._persist_raw_event(session, raw_event, db_run.id)
                stats.raw_events_collected += 1
                self.bus.publish(PipelineEvent(
                    event_type="raw_event.created",
                    payload_id=db_raw.id,
                    metadata={"source": raw_event.source, "event_type": raw_event.event_type},
                ))

                # Stage 2: Normalize
                findings = self.normalizers.normalize(raw_event)
                for finding in findings:
                    finding.raw_event_id = db_raw.id
                    db_finding = self._persist_finding(session, finding)
                    stats.findings_normalized += 1
                    self.bus.publish(PipelineEvent(
                        event_type="finding.normalized",
                        payload_id=db_finding.id,
                        metadata={"severity": finding.severity, "type": finding.observation_type},
                    ))

                    # Stage 3: Map to controls
                    mapped = self.mapper.map(finding)
                    for mapping in mapped.mappings:
                        self._persist_mapping(session, mapping)
                        stats.controls_mapped += 1

                    if mapped.mappings:
                        self.bus.publish(PipelineEvent(
                            event_type="finding.mapped",
                            payload_id=db_finding.id,
                            metadata={
                                "mapping_count": len(mapped.mappings),
                                "frameworks": list({m.framework for m in mapped.mappings}),
                            },
                        ))

                    # Stage 4: Assess
                    results = self.assessor.assess(mapped, raw_data=raw_event.raw_data)
                    for result in results:
                        db_result = self._persist_result(session, result)
                        stats.results_assessed += 1
                        self.bus.publish(PipelineEvent(
                            event_type="control.assessed",
                            payload_id=db_result.id,
                            metadata={
                                "framework": result.framework,
                                "control_id": result.control_id,
                                "status": result.status,
                                "severity": result.severity,
                            },
                        ))

        session.flush()
        stats.completed_at = datetime.now(timezone.utc)
        log.info(
            "Pipeline run complete: %d raw events → %d findings → %d mappings → %d results (%.1fs)",
            stats.raw_events_collected,
            stats.findings_normalized,
            stats.controls_mapped,
            stats.results_assessed,
            stats.duration_seconds or 0,
        )
        return stats

    # -- Persistence helpers --

    def _persist_connector_run(self, session: Session, cr: ConnectorResult) -> models.ConnectorRun:
        db_run = models.ConnectorRun(
            id=cr.id,
            connector_name=cr.connector_name,
            source=cr.source,
            source_type=cr.source_type.value if hasattr(cr.source_type, "value") else cr.source_type,
            provider=cr.provider,
            status=cr.status,
            event_count=cr.event_count,
            error_count=len(cr.errors),
            errors=cr.errors,
            started_at=cr.started_at,
            completed_at=cr.completed_at,
            duration_seconds=cr.duration_seconds,
        )
        session.add(db_run)
        session.flush()
        return db_run

    def _persist_raw_event(
        self, session: Session, raw: RawEventData, connector_run_id: str
    ) -> models.RawEvent:
        db_raw = models.RawEvent(
            id=raw.id,
            connector_run_id=connector_run_id,
            source=raw.source,
            source_type=raw.source_type.value if hasattr(raw.source_type, "value") else raw.source_type,
            provider=raw.provider,
            event_type=raw.event_type,
            raw_data=raw.raw_data,
            sha256=raw.sha256,
            ingested_at=raw.observed_at,
        )
        session.add(db_raw)
        session.flush()
        return db_raw

    def _persist_finding(self, session: Session, f: FindingData) -> models.Finding:
        db_finding = models.Finding(
            id=f.id,
            raw_event_id=f.raw_event_id,
            observation_type=f.observation_type,
            title=f.title,
            detail=f.detail,
            resource_id=f.resource_id,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            account_id=f.account_id,
            region=f.region,
            source=f.source,
            source_type=f.source_type.value if hasattr(f.source_type, "value") else f.source_type,
            provider=f.provider,
            severity=f.severity,
            confidence=f.confidence,
            observed_at=f.observed_at,
            sha256=f.sha256,
        )
        session.add(db_finding)
        session.flush()
        return db_finding

    def _persist_mapping(self, session: Session, m) -> models.ControlMapping:
        db_mapping = models.ControlMapping(
            id=m.id,
            finding_id=m.finding_id,
            framework=m.framework,
            control_id=m.control_id,
            control_family=m.control_family,
            mapping_method=m.mapping_method,
            confidence=m.confidence,
            crosswalk_path=m.crosswalk_path or None,
            monitoring_frequency=m.monitoring_frequency or None,
        )
        session.add(db_mapping)
        session.flush()
        return db_mapping

    def _persist_result(self, session: Session, r: ControlResultData) -> models.ControlResult:
        db_result = models.ControlResult(
            id=r.id,
            finding_id=r.finding_id,
            control_mapping_id=r.control_mapping_id,
            framework=r.framework,
            control_id=r.control_id,
            status=r.status,
            severity=r.severity,
            assertion_name=r.assertion_name or None,
            assertion_passed=r.assertion_passed,
            assertion_findings=r.assertion_findings or None,
            ai_assessment=r.ai_assessment or None,
            ai_confidence=r.ai_confidence,
            ai_model=r.ai_model or None,
            remediation_summary=r.remediation_summary or None,
            remediation_steps=r.remediation_steps or None,
            console_path=r.console_path or None,
            evidence_ids=r.evidence_ids or None,
            assessed_at=r.assessed_at,
            assessor=r.assessor,
        )
        session.add(db_result)
        session.flush()
        return db_result
