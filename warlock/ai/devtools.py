"""AI DevTools for debugging and inspecting AI assessments.

Provides tooling for compliance engineers and developers to inspect
AI assessment internals: prompts used, model responses, confidence
distributions, token usage estimates, and side-by-side comparisons.

Public API::

    from warlock.ai.devtools import AIDevTools

    devtools = AIDevTools(session)
    info = devtools.inspect_assessment("abc-123")
    comparison = devtools.compare_assessments("abc-123", "def-456")
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class AssessmentInfo:
    """Full inspection of a single AI assessment."""

    control_result_id: str
    framework: str
    control_id: str
    status: str
    severity: str

    # Assessment details
    assessor: str
    assertion_name: str | None
    assertion_passed: bool | None
    assertion_findings: Any

    # AI-specific fields
    ai_assessment: str | None
    ai_confidence: float | None
    ai_model: str | None

    # Prompt reconstruction
    prompt_context: dict[str, Any]

    # Remediation
    remediation_summary: str | None
    remediation_steps: Any

    # Timestamps
    assessed_at: datetime | None

    # Metadata
    evidence_ids: Any
    finding_id: str


@dataclass
class AssessmentComparison:
    """Side-by-side comparison of two AI assessments."""

    left: AssessmentInfo
    right: AssessmentInfo
    differences: list[str]
    confidence_delta: float | None
    same_framework: bool
    same_control: bool
    same_model: bool


@dataclass
class ConfidenceBucket:
    """A bucket in the confidence distribution histogram."""

    range_low: float
    range_high: float
    count: int
    percentage: float
    control_ids: list[str]


@dataclass
class ConfidenceAnalysisResult:
    """Distribution analysis of AI confidence scores."""

    total_assessments: int
    ai_assessed_count: int
    mean_confidence: float
    median_confidence: float
    std_deviation: float
    min_confidence: float
    max_confidence: float
    distribution: list[ConfidenceBucket]
    outliers_low: list[AssessmentInfo]  # Below mean - 2*std
    framework_filter: str | None


@dataclass
class TokenUsageReport:
    """Estimated token usage from assessment history."""

    period_days: int
    total_ai_assessments: int
    estimated_input_tokens: int
    estimated_output_tokens: int
    estimated_total_tokens: int
    by_framework: dict[str, dict[str, int]]
    by_model: dict[str, dict[str, int]]
    avg_tokens_per_assessment: int


@dataclass
class PromptPreview:
    """Preview of the prompt that would be generated for a control."""

    framework: str
    control_id: str
    system_prompt: str
    user_prompt_template: str
    max_tokens: int
    response_format: str
    available_context: dict[str, Any]


# ---------------------------------------------------------------------------
# Token estimation constants
# ---------------------------------------------------------------------------

# Rough estimates: 1 token ~= 4 characters for English text
_CHARS_PER_TOKEN = 4
_AVG_AI_ASSESSMENT_INPUT_TOKENS = 800
_AVG_AI_ASSESSMENT_OUTPUT_TOKENS = 400


# ---------------------------------------------------------------------------
# AIDevTools
# ---------------------------------------------------------------------------


class AIDevTools:
    """AI assessment debugging and inspection toolkit.

    Provides read-only inspection of AI assessment results stored in the
    database.  No AI calls are made -- this tool works with historical
    assessment data.

    Parameters
    ----------
    session:
        An active SQLAlchemy session for database queries.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- Public API ---------------------------------------------------------

    def inspect_assessment(self, control_result_id: str) -> AssessmentInfo | None:
        """Show detailed information about a single AI assessment.

        Retrieves the control result and reconstructs the assessment
        context including the prompt that would have been used, the
        model response, confidence score, and reasoning.

        Parameters
        ----------
        control_result_id:
            UUID or prefix of the control result to inspect.

        Returns
        -------
        AssessmentInfo or None
            Full assessment details, or ``None`` if not found.
        """
        row = (
            self._session.query(ControlResult)
            .filter(ControlResult.id.startswith(control_result_id))
            .first()
        )
        if row is None:
            return None

        return self._build_assessment_info(row)

    def compare_assessments(
        self,
        cr_id_1: str,
        cr_id_2: str,
    ) -> AssessmentComparison | None:
        """Side-by-side comparison of two AI assessments.

        Compares status, confidence, model, reasoning, and remediation
        between two control results to help debug inconsistencies.

        Parameters
        ----------
        cr_id_1:
            UUID or prefix of the first control result.
        cr_id_2:
            UUID or prefix of the second control result.

        Returns
        -------
        AssessmentComparison or None
            Comparison result, or ``None`` if either result is not found.
        """
        left_row = (
            self._session.query(ControlResult).filter(ControlResult.id.startswith(cr_id_1)).first()
        )
        right_row = (
            self._session.query(ControlResult).filter(ControlResult.id.startswith(cr_id_2)).first()
        )

        if left_row is None or right_row is None:
            return None

        left = self._build_assessment_info(left_row)
        right = self._build_assessment_info(right_row)

        differences = self._compute_differences(left, right)

        left_conf = left.ai_confidence if left.ai_confidence is not None else 0.0
        right_conf = right.ai_confidence if right.ai_confidence is not None else 0.0
        confidence_delta: float | None = None
        if left.ai_confidence is not None and right.ai_confidence is not None:
            confidence_delta = right_conf - left_conf

        return AssessmentComparison(
            left=left,
            right=right,
            differences=differences,
            confidence_delta=confidence_delta,
            same_framework=left.framework == right.framework,
            same_control=left.control_id == right.control_id,
            same_model=left.ai_model == right.ai_model,
        )

    def prompt_viewer(
        self,
        framework: str,
        control_id: str,
    ) -> PromptPreview:
        """Show what prompt would be generated for a given control.

        Reconstructs the prompt template and available context for the
        specified framework/control combination.  Does not make any AI
        calls.

        Parameters
        ----------
        framework:
            Framework identifier (e.g. ``nist_800_53``).
        control_id:
            Control identifier (e.g. ``AC-2``).

        Returns
        -------
        PromptPreview
            The prompt template and available context.
        """
        from warlock.ai.tasks import TASK_PROMPTS
        from warlock.ai.types import AITask

        task_prompt = TASK_PROMPTS.get(AITask.COMPLIANCE_ASSESSMENT)

        system_prompt = task_prompt.system if task_prompt else "(no prompt registered)"
        user_template = task_prompt.user_template if task_prompt else "(no template registered)"
        max_tokens = task_prompt.max_tokens if task_prompt else 1024
        response_format = task_prompt.response_format if task_prompt else "json"

        # Gather available context from the database
        results = (
            self._session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
            )
            .order_by(ControlResult.assessed_at.desc())
            .limit(5)
            .all()
        )

        context: dict[str, Any] = {
            "framework": framework,
            "control_id": control_id,
            "existing_results_count": len(results),
            "latest_status": results[0].status if results else "no_data",
            "latest_assessor": results[0].assessor if results else "none",
            "evidence_ids": results[0].evidence_ids if results else [],
        }

        return PromptPreview(
            framework=framework,
            control_id=control_id,
            system_prompt=system_prompt,
            user_prompt_template=user_template,
            max_tokens=max_tokens,
            response_format=response_format,
            available_context=context,
        )

    def confidence_analysis(
        self,
        framework: str | None = None,
    ) -> ConfidenceAnalysisResult:
        """Analyze the distribution of AI confidence scores.

        Computes mean, median, standard deviation, and a histogram of
        confidence scores across AI-assessed control results.  Identifies
        outliers below ``mean - 2 * std_deviation``.

        Parameters
        ----------
        framework:
            Optional framework filter.

        Returns
        -------
        ConfidenceAnalysisResult
            Statistical analysis of confidence distribution.
        """
        q = self._session.query(ControlResult).filter(
            ControlResult.ai_confidence.isnot(None),
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)

        rows = q.limit(10000).all()

        total_q = self._session.query(func.count(ControlResult.id))
        if framework:
            total_q = total_q.filter(ControlResult.framework == framework)
        total_assessments = total_q.scalar() or 0

        if not rows:
            return ConfidenceAnalysisResult(
                total_assessments=total_assessments,
                ai_assessed_count=0,
                mean_confidence=0.0,
                median_confidence=0.0,
                std_deviation=0.0,
                min_confidence=0.0,
                max_confidence=0.0,
                distribution=[],
                outliers_low=[],
                framework_filter=framework,
            )

        confidences = sorted([r.ai_confidence for r in rows if r.ai_confidence is not None])
        n = len(confidences)

        mean_val = sum(confidences) / n
        median_val = (
            confidences[n // 2]
            if n % 2 == 1
            else (confidences[n // 2 - 1] + confidences[n // 2]) / 2
        )
        variance = sum((c - mean_val) ** 2 for c in confidences) / n if n > 0 else 0.0
        std_val = math.sqrt(variance)
        min_val = confidences[0]
        max_val = confidences[-1]

        # Build histogram buckets (10 buckets: 0.0-0.1, 0.1-0.2, ..., 0.9-1.0)
        buckets: list[ConfidenceBucket] = []
        for i in range(10):
            low = i * 0.1
            high = (i + 1) * 0.1
            bucket_rows = [
                r
                for r in rows
                if r.ai_confidence is not None
                and low <= r.ai_confidence < (high if i < 9 else high + 0.01)
            ]
            buckets.append(
                ConfidenceBucket(
                    range_low=round(low, 1),
                    range_high=round(high, 1),
                    count=len(bucket_rows),
                    percentage=len(bucket_rows) / n * 100 if n else 0.0,
                    control_ids=[r.control_id for r in bucket_rows[:5]],
                )
            )

        # Identify outliers (below mean - 2*std)
        outlier_threshold = mean_val - 2 * std_val
        outlier_rows = [
            r for r in rows if r.ai_confidence is not None and r.ai_confidence < outlier_threshold
        ]
        outliers = [self._build_assessment_info(r) for r in outlier_rows[:10]]

        return ConfidenceAnalysisResult(
            total_assessments=total_assessments,
            ai_assessed_count=n,
            mean_confidence=round(mean_val, 4),
            median_confidence=round(median_val, 4),
            std_deviation=round(std_val, 4),
            min_confidence=round(min_val, 4),
            max_confidence=round(max_val, 4),
            distribution=buckets,
            outliers_low=outliers,
            framework_filter=framework,
        )

    def token_usage_report(
        self,
        days: int = 30,
    ) -> TokenUsageReport:
        """Estimate token usage from AI assessment history.

        Provides rough token estimates based on the number and size of
        AI assessments stored in the database.  Actual token counts are
        not stored in control results, so this uses heuristics based on
        assessment text length.

        Parameters
        ----------
        days:
            Look-back window in days.

        Returns
        -------
        TokenUsageReport
            Estimated token usage breakdown.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        rows = (
            self._session.query(ControlResult)
            .filter(
                ControlResult.ai_confidence.isnot(None),
                ControlResult.assessed_at >= since,
            )
            .limit(10000)
            .all()
        )

        total_input = 0
        total_output = 0
        by_framework: dict[str, dict[str, int]] = {}
        by_model: dict[str, dict[str, int]] = {}

        for r in rows:
            # Estimate tokens from assessment text length
            assessment_text = r.ai_assessment or ""
            output_tokens = max(
                len(assessment_text) // _CHARS_PER_TOKEN, _AVG_AI_ASSESSMENT_OUTPUT_TOKENS
            )
            input_tokens = _AVG_AI_ASSESSMENT_INPUT_TOKENS

            total_input += input_tokens
            total_output += output_tokens

            # By framework
            fw_stats = by_framework.setdefault(r.framework, {"input": 0, "output": 0, "count": 0})
            fw_stats["input"] += input_tokens
            fw_stats["output"] += output_tokens
            fw_stats["count"] += 1

            # By model
            model_name = r.ai_model or "unknown"
            model_stats = by_model.setdefault(model_name, {"input": 0, "output": 0, "count": 0})
            model_stats["input"] += input_tokens
            model_stats["output"] += output_tokens
            model_stats["count"] += 1

        total = total_input + total_output
        avg = total // len(rows) if rows else 0

        return TokenUsageReport(
            period_days=days,
            total_ai_assessments=len(rows),
            estimated_input_tokens=total_input,
            estimated_output_tokens=total_output,
            estimated_total_tokens=total,
            by_framework=by_framework,
            by_model=by_model,
            avg_tokens_per_assessment=avg,
        )

    # -- Internals ----------------------------------------------------------

    def _build_assessment_info(self, row: ControlResult) -> AssessmentInfo:
        """Convert a ControlResult row into an AssessmentInfo dataclass."""
        assessed_at = ensure_aware(row.assessed_at)

        # Reconstruct the prompt context from available data
        prompt_context: dict[str, Any] = {
            "framework": row.framework,
            "control_id": row.control_id,
            "finding_id": row.finding_id,
            "status": row.status,
            "severity": row.severity,
            "assessor": row.assessor,
        }
        if row.assertion_name:
            prompt_context["assertion_name"] = row.assertion_name
            prompt_context["assertion_passed"] = row.assertion_passed
        if row.evidence_ids:
            prompt_context["evidence_ids"] = row.evidence_ids

        return AssessmentInfo(
            control_result_id=row.id,
            framework=row.framework,
            control_id=row.control_id,
            status=row.status,
            severity=row.severity,
            assessor=row.assessor,
            assertion_name=row.assertion_name,
            assertion_passed=row.assertion_passed,
            assertion_findings=row.assertion_findings,
            ai_assessment=row.ai_assessment,
            ai_confidence=row.ai_confidence,
            ai_model=row.ai_model,
            prompt_context=prompt_context,
            remediation_summary=row.remediation_summary,
            remediation_steps=row.remediation_steps,
            assessed_at=assessed_at,
            evidence_ids=row.evidence_ids,
            finding_id=row.finding_id,
        )

    def _compute_differences(
        self,
        left: AssessmentInfo,
        right: AssessmentInfo,
    ) -> list[str]:
        """List the meaningful differences between two assessments."""
        diffs: list[str] = []

        if left.status != right.status:
            diffs.append(f"Status: '{left.status}' vs '{right.status}'")
        if left.severity != right.severity:
            diffs.append(f"Severity: '{left.severity}' vs '{right.severity}'")
        if left.ai_confidence != right.ai_confidence:
            l_conf = f"{left.ai_confidence:.2f}" if left.ai_confidence is not None else "N/A"
            r_conf = f"{right.ai_confidence:.2f}" if right.ai_confidence is not None else "N/A"
            diffs.append(f"AI confidence: {l_conf} vs {r_conf}")
        if left.ai_model != right.ai_model:
            diffs.append(f"AI model: '{left.ai_model or 'N/A'}' vs '{right.ai_model or 'N/A'}'")
        if left.assessor != right.assessor:
            diffs.append(f"Assessor: '{left.assessor}' vs '{right.assessor}'")
        if left.assertion_passed != right.assertion_passed:
            diffs.append(f"Assertion passed: {left.assertion_passed} vs {right.assertion_passed}")
        if (left.ai_assessment or "") != (right.ai_assessment or ""):
            diffs.append("AI assessment text differs")
        if (left.remediation_summary or "") != (right.remediation_summary or ""):
            diffs.append("Remediation summary differs")

        if not diffs:
            diffs.append("No significant differences detected")

        return diffs
