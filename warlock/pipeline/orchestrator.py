"""The spine. Wires Stage 1 → 2 → 3 → 4 together via the event bus."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.connectors.base import ConnectorRegistry, ConnectorResult, RawEventData
from warlock.normalizers.base import FindingData, NormalizerRegistry
from warlock.mappers.control_mapper import ControlMapper
from warlock.assessors.engine import Assessor, ControlResultData
from warlock.pipeline.bus import EventBus, PipelineEvent
from warlock.db import models

# Optional OPA compliance evaluation imports (may not be initialized)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from warlock.assessors.opa_evaluator import OPAComplianceEvaluator

log = logging.getLogger(__name__)


class PipelineConcurrencyError(RuntimeError):
    """Raised when a pipeline run cannot acquire the concurrency lock."""


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

    # Normalizer quality counters
    normalizer_failures: int = 0       # raw events where normalization raised an exception
    events_without_findings: int = 0   # raw events that produced zero findings

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
        opa_evaluator: OPAComplianceEvaluator | None = None,
    ) -> None:
        self.connectors = connectors
        self.normalizers = normalizers
        self.mapper = mapper
        self.assessor = assessor
        self.bus = bus
        self.opa_evaluator = opa_evaluator

    def run(self, session: Session) -> PipelineRunStats:
        """Execute the full pipeline. One pass, all connectors.

        Transaction model: this method uses an all-or-nothing approach. All
        four stages (Ingest, Normalize, Map, Assess) run within a single
        database session. The caller's context manager (get_session) commits on
        success or rolls back the entire run on any unhandled exception. This
        is intentional: a partial pipeline run would leave orphaned findings
        without assessments, which is worse than no run at all. If a connector
        fails, its errors are recorded in ConnectorRun.errors and the pipeline
        continues with the remaining connectors; only a session-level exception
        triggers a full rollback.

        Concurrency: acquires an advisory lock before executing to prevent
        overlapping pipeline runs. For SQLite, a file lock is used. For
        PostgreSQL, pg_advisory_lock is used. Raises PipelineConcurrencyError
        if the lock cannot be acquired (another run is in progress).
        """
        self._acquire_concurrency_lock(session)

        stats = PipelineRunStats()

        # Enhancement #8: propagate run_id into every log record for this run
        from warlock.logging_config import correlation_id as _correlation_id
        if stats.run_id:
            _correlation_id.set(stats.run_id)

        log.info("Pipeline run starting")

        # Accumulate already-normalized findings so Stage 5 (OPA) can reuse them
        # directly instead of re-normalizing the same raw events a second time.
        all_normalized_findings: list[FindingData] = []

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
                try:
                    findings = self.normalizers.normalize(raw_event)
                except Exception as norm_exc:
                    stats.normalizer_failures += 1
                    stats.errors.append(f"Normalization failed for {db_raw.id}: {norm_exc}")
                    log.exception("Normalizer failed for raw event %s", db_raw.id)
                    continue
                if not findings:
                    stats.events_without_findings += 1
                # Accumulate for OPA stage (avoids re-normalization later)
                all_normalized_findings.extend(findings)
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

        # Stage 5 (optional): OPA compliance evaluation across all frameworks
        if self.opa_evaluator is not None:
            opa_results = self._evaluate_opa_compliance(
                session, connector_results, all_normalized_findings
            )
            stats.results_assessed += len(opa_results)

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

    # -- Concurrency lock --

    def _acquire_concurrency_lock(self, session: Session) -> None:
        """Acquire a single-instance advisory lock for pipeline execution.

        For SQLite databases, uses a file lock (fcntl.flock) on a temporary
        lock file so concurrent processes cannot run the pipeline simultaneously.
        For PostgreSQL, uses pg_advisory_lock with a fixed integer key so that
        the lock is automatically released when the session ends.

        Raises PipelineConcurrencyError if the lock cannot be acquired (i.e.,
        another pipeline run is already in progress).
        """
        dialect = session.bind.dialect.name if session.bind else "sqlite"

        if dialect == "postgresql":
            # pg_advisory_lock blocks until the lock is available; use
            # pg_try_advisory_lock to detect contention immediately.
            from sqlalchemy import text
            result = session.execute(
                text("SELECT pg_try_advisory_lock(7301839201)")  # fixed Warlock pipeline key
            ).scalar()
            if not result:
                raise PipelineConcurrencyError(
                    "Another pipeline run is already in progress "
                    "(pg_try_advisory_lock returned false). "
                    "Wait for the current run to complete."
                )
        else:
            # SQLite: use a file-based lock via fcntl (POSIX only).
            try:
                import fcntl
                lock_path = os.path.join(
                    os.environ.get("TMPDIR", "/tmp"), "warlock_pipeline.lock"
                )
                lock_file = open(lock_path, "w")
                try:
                    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    lock_file.close()
                    raise PipelineConcurrencyError(
                        "Another pipeline run is already in progress "
                        "(file lock could not be acquired). "
                        "Wait for the current run to complete."
                    )
                # Store the lock file on the instance so it stays open (and
                # locked) for the duration of the run. The OS releases the
                # lock when the file object is garbage-collected or closed.
                self._lock_file = lock_file
            except ImportError:
                # fcntl is not available on Windows — skip locking.
                log.warning(
                    "fcntl not available; pipeline concurrency lock is disabled on this platform"
                )

    # -- Integrity verification --

    def verify_integrity(self, session: Session, run_id: str | None = None) -> dict:
        """Verify SHA-256 hashes of all stored RawEvent records.

        Re-computes the SHA-256 for each RawEvent and compares to the stored
        hash to detect evidence tampering. Records a verified_at timestamp
        and logs results with the run correlation ID.

        Args:
            session: Database session.
            run_id: Optional correlation ID for logging context. If provided,
                    sets the correlation ID so all log lines include it.

        Returns a dict with keys:
          - total: number of records checked
          - passed: records whose hash matched
          - failed: list of IDs whose hash did not match
          - verified_at: ISO-8601 timestamp of when verification completed
          - run_id: correlation ID used (if any)
        """
        import hashlib
        import json

        # Set correlation ID for log context if provided
        correlation_token = None
        if run_id:
            from warlock.logging_config import correlation_id as _correlation_id
            correlation_token = _correlation_id.set(run_id)

        log.info("Evidence integrity verification starting")

        failed: list[str] = []
        total = 0
        passed = 0

        for raw_event in session.query(models.RawEvent).yield_per(500):
            total += 1
            payload = json.dumps(raw_event.raw_data, sort_keys=True, default=str).encode()
            computed = hashlib.sha256(payload).hexdigest()
            if computed == raw_event.sha256:
                passed += 1
            else:
                failed.append(raw_event.id)
                log.warning(
                    "Integrity check FAILED for RawEvent %s: stored=%s computed=%s",
                    raw_event.id, raw_event.sha256, computed,
                )

        verified_at = datetime.now(timezone.utc)

        if failed:
            log.error(
                "Evidence integrity verification FAILED: %d/%d records tampered",
                len(failed), total,
            )
        else:
            log.info(
                "Evidence integrity verification PASSED: %d/%d records verified",
                passed, total,
            )

        # Reset correlation ID if we set it
        if correlation_token is not None:
            from warlock.logging_config import correlation_id as _correlation_id
            _correlation_id.set("")

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "verified_at": verified_at.isoformat(),
            "run_id": run_id,
        }

    def cli_verify_integrity(self, session: Session, run_id: str | None = None) -> dict:
        """CLI-callable entry point for ``warlock verify-integrity``.

        Wraps :meth:`verify_integrity` with structured output suitable for
        console display. The CLI command itself will be wired separately.

        Args:
            session: Database session.
            run_id: Optional correlation ID for logging and result tagging.

        Returns:
            The same dict as verify_integrity, plus an ``ok`` boolean.
        """
        if run_id is None:
            from uuid import uuid4
            run_id = str(uuid4())

        result = self.verify_integrity(session, run_id=run_id)
        result["ok"] = len(result["failed"]) == 0
        return result

    # -- OPA compliance evaluation --

    def _evaluate_opa_compliance(
        self,
        session: Session,
        connector_results: list[ConnectorResult],
        normalized_findings: list[FindingData] | None = None,
    ) -> list[ControlResultData]:
        """Run OPA compliance evaluation across all frameworks.

        Assembles normalized_data from raw events and the already-normalized
        findings collected during Stage 2, then evaluates all registered Rego
        policies against OPA.  Passing *normalized_findings* avoids running the
        normalizer a second time over every raw event.
        """
        from warlock.assessors.data_assembler import NormalizedDataAssembler
        from warlock.assessors.policy_registry import get_policy_registry
        from warlock.config import get_settings

        settings = get_settings()
        results: list[ControlResultData] = []

        try:
            # Gather all raw events from connector results
            all_raw_events: list[RawEventData] = []
            for cr in connector_results:
                all_raw_events.extend(cr.events)

            # Use pre-collected findings from Stage 2; fall back to re-normalizing
            # only when this method is called without them (e.g. in tests).
            if normalized_findings is not None:
                all_findings: list[FindingData] = normalized_findings
            else:
                all_findings = []
                for raw_event in all_raw_events:
                    try:
                        all_findings.extend(self.normalizers.normalize(raw_event))
                    except Exception:
                        pass  # Already logged during main loop

            # Assemble the normalized data document
            assembler = NormalizedDataAssembler()
            normalized_data = assembler.assemble(all_findings, all_raw_events)

            # Get the policy registry
            registry = get_policy_registry(
                policies_dir=settings.opa_bundle_path if settings.opa_bundle_path else None
            )
            policy_map = registry.policy_map

            # Determine which frameworks to evaluate
            frameworks = settings.opa_frameworks if settings.opa_frameworks else None

            # Evaluate
            opa_results = self.opa_evaluator.evaluate_all(
                normalized_data=normalized_data,
                policy_map=policy_map,
                frameworks=frameworks,
            )

            # Persist results
            for result in opa_results:
                db_result = self._persist_result(session, result)
                results.append(result)
                self.bus.publish(PipelineEvent(
                    event_type="control.assessed",
                    payload_id=db_result.id,
                    metadata={
                        "framework": result.framework,
                        "control_id": result.control_id,
                        "status": result.status,
                        "severity": result.severity,
                        "assessor": result.assessor,
                    },
                ))

            log.info("OPA compliance evaluation: %d results", len(results))

        except Exception:
            log.exception("OPA compliance evaluation failed")

        return results

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
