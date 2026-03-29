"""Pipeline data quality validation.

Runs structural checks on pipeline artifacts at each stage:
- Null required fields
- Duplicate detection (same ID seen twice in a run)
- Severity value validation (must be in allowed set)
- Timestamp sanity (not in the future, not unreasonably old)

Wired into the pipeline after each stage via the event bus or
called directly by the orchestrator.

Usage::

    from warlock.pipeline.data_quality import DataQualityChecker

    checker = DataQualityChecker()
    issues = checker.check_raw_event(raw_event_data)
    issues = checker.check_finding(finding_data)
    issues = checker.check_control_result(result_data)

    report = checker.report()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}
VALID_STATUSES = {"compliant", "non_compliant", "partial", "not_assessed", "not_applicable"}
# Timestamps older than this are flagged as suspicious
MAX_AGE_DAYS = 365 * 5  # 5 years


@dataclass
class DQIssue:
    """A single data quality issue."""

    stage: str  # "collect", "normalize", "map", "assess"
    artifact_type: str  # "raw_event", "finding", "control_result"
    artifact_id: str
    check: str  # "null_field", "duplicate", "invalid_severity", "timestamp_future", etc.
    message: str
    severity: str = "warning"  # "warning" or "error"


@dataclass
class DataQualityChecker:
    """Accumulates data quality issues during a pipeline run."""

    _issues: list[DQIssue] = field(default_factory=list)
    _seen_raw_event_ids: set[str] = field(default_factory=set)
    _seen_finding_ids: set[str] = field(default_factory=set)
    _seen_result_ids: set[str] = field(default_factory=set)

    def check_raw_event(self, evt: Any) -> list[DQIssue]:
        """Validate a raw event. Returns new issues found."""
        issues: list[DQIssue] = []
        eid = getattr(evt, "id", None) or ""

        # Null required fields
        for field_name in ("id", "source", "event_type", "raw_data"):
            val = getattr(evt, field_name, None)
            if val is None or val == "":
                issue = DQIssue(
                    stage="collect",
                    artifact_type="raw_event",
                    artifact_id=str(eid),
                    check="null_field",
                    message=f"Required field '{field_name}' is null/empty",
                    severity="error",
                )
                issues.append(issue)

        # Duplicate detection
        if eid and eid in self._seen_raw_event_ids:
            issue = DQIssue(
                stage="collect",
                artifact_type="raw_event",
                artifact_id=str(eid),
                check="duplicate",
                message=f"Duplicate raw_event ID: {eid}",
                severity="error",
            )
            issues.append(issue)
        if eid:
            self._seen_raw_event_ids.add(eid)

        self._issues.extend(issues)
        return issues

    def check_finding(self, finding: Any) -> list[DQIssue]:
        """Validate a normalized finding. Returns new issues found."""
        issues: list[DQIssue] = []
        fid = getattr(finding, "id", None) or ""

        # Null required fields
        for field_name in ("id", "title", "source", "severity"):
            val = getattr(finding, field_name, None)
            if val is None or val == "":
                issue = DQIssue(
                    stage="normalize",
                    artifact_type="finding",
                    artifact_id=str(fid),
                    check="null_field",
                    message=f"Required field '{field_name}' is null/empty",
                    severity="error",
                )
                issues.append(issue)

        # Severity validation
        sev = getattr(finding, "severity", None)
        if sev and str(sev).lower() not in VALID_SEVERITIES:
            issue = DQIssue(
                stage="normalize",
                artifact_type="finding",
                artifact_id=str(fid),
                check="invalid_severity",
                message=f"Invalid severity '{sev}' (expected one of {VALID_SEVERITIES})",
                severity="warning",
            )
            issues.append(issue)

        # Timestamp sanity
        observed = getattr(finding, "observed_at", None)
        if observed:
            issues.extend(
                self._check_timestamp(observed, "observed_at", "normalize", "finding", str(fid))
            )

        # Duplicate detection
        if fid and fid in self._seen_finding_ids:
            issue = DQIssue(
                stage="normalize",
                artifact_type="finding",
                artifact_id=str(fid),
                check="duplicate",
                message=f"Duplicate finding ID: {fid}",
                severity="error",
            )
            issues.append(issue)
        if fid:
            self._seen_finding_ids.add(fid)

        self._issues.extend(issues)
        return issues

    def check_control_result(self, result: Any) -> list[DQIssue]:
        """Validate a control result. Returns new issues found."""
        issues: list[DQIssue] = []
        rid = getattr(result, "id", None) or ""

        # Null required fields
        for field_name in ("id", "framework", "control_id", "status"):
            val = getattr(result, field_name, None)
            if val is None or val == "":
                issue = DQIssue(
                    stage="assess",
                    artifact_type="control_result",
                    artifact_id=str(rid),
                    check="null_field",
                    message=f"Required field '{field_name}' is null/empty",
                    severity="error",
                )
                issues.append(issue)

        # Status validation
        status = getattr(result, "status", None)
        if status and str(status) not in VALID_STATUSES:
            issue = DQIssue(
                stage="assess",
                artifact_type="control_result",
                artifact_id=str(rid),
                check="invalid_status",
                message=f"Invalid status '{status}' (expected one of {VALID_STATUSES})",
                severity="error",
            )
            issues.append(issue)

        # Duplicate detection
        if rid and rid in self._seen_result_ids:
            issue = DQIssue(
                stage="assess",
                artifact_type="control_result",
                artifact_id=str(rid),
                check="duplicate",
                message=f"Duplicate control_result ID: {rid}",
                severity="warning",
            )
            issues.append(issue)
        if rid:
            self._seen_result_ids.add(rid)

        self._issues.extend(issues)
        return issues

    def _check_timestamp(
        self,
        ts: Any,
        field_name: str,
        stage: str,
        artifact_type: str,
        artifact_id: str,
    ) -> list[DQIssue]:
        """Check a timestamp for sanity (not future, not too old)."""
        issues: list[DQIssue] = []
        now = datetime.now(timezone.utc)

        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                issues.append(
                    DQIssue(
                        stage=stage,
                        artifact_type=artifact_type,
                        artifact_id=artifact_id,
                        check="invalid_timestamp",
                        message=f"Cannot parse '{field_name}' as datetime: {ts}",
                        severity="warning",
                    )
                )
                return issues

        if not isinstance(ts, datetime):
            return issues

        # Make tz-aware for comparison
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        if ts > now + timedelta(hours=24):
            issues.append(
                DQIssue(
                    stage=stage,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    check="timestamp_future",
                    message=f"'{field_name}' is in the future: {ts.isoformat()}",
                    severity="warning",
                )
            )

        cutoff = now - timedelta(days=MAX_AGE_DAYS)
        if ts < cutoff:
            issues.append(
                DQIssue(
                    stage=stage,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    check="timestamp_stale",
                    message=f"'{field_name}' is older than {MAX_AGE_DAYS} days: {ts.isoformat()}",
                    severity="warning",
                )
            )

        return issues

    @property
    def issues(self) -> list[DQIssue]:
        """All accumulated issues."""
        return list(self._issues)

    @property
    def error_count(self) -> int:
        """Number of error-severity issues."""
        return sum(1 for i in self._issues if i.severity == "error")

    @property
    def warning_count(self) -> int:
        """Number of warning-severity issues."""
        return sum(1 for i in self._issues if i.severity == "warning")

    def report(self) -> dict[str, Any]:
        """Generate a summary report of all data quality issues."""
        by_check: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        for issue in self._issues:
            by_check[issue.check] = by_check.get(issue.check, 0) + 1
            by_stage[issue.stage] = by_stage.get(issue.stage, 0) + 1

        return {
            "total_issues": len(self._issues),
            "errors": self.error_count,
            "warnings": self.warning_count,
            "by_check": by_check,
            "by_stage": by_stage,
            "raw_events_checked": len(self._seen_raw_event_ids),
            "findings_checked": len(self._seen_finding_ids),
            "results_checked": len(self._seen_result_ids),
        }

    def clear(self) -> None:
        """Reset all state for a new pipeline run."""
        self._issues.clear()
        self._seen_raw_event_ids.clear()
        self._seen_finding_ids.clear()
        self._seen_result_ids.clear()
