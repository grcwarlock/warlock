"""Layer 3 — Assessment.

Two-tier evaluation:
  Tier 1: Deterministic assertions (fast, auditable, reproducible)
  Tier 2: AI reasoning (optional, for when Tier 1 is insufficient)

Supports parent→child control inheritance: when a parent control (AC-2)
is assessed, child enhancements (AC-2(1), AC-2(2)) can inherit the
parent's status if they have no assertion of their own.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from warlock.assessors.ai_reasoning import AIReasoner
from warlock.mappers.control_mapper import ControlMappingData, MappedFinding
from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Assessment output
# ---------------------------------------------------------------------------

@dataclass
class ControlResultData:
    finding_id: str
    control_mapping_id: str
    framework: str
    control_id: str

    # Determination
    status: str = "not_assessed"   # compliant, non_compliant, partial, not_assessed, not_applicable
    severity: str = "info"

    # Tier 1: assertion
    assertion_name: str = ""
    assertion_passed: bool | None = None
    assertion_findings: list[str] = field(default_factory=list)

    # Tier 2: AI (nullable)
    ai_assessment: str = ""
    ai_confidence: float | None = None
    ai_model: str = ""

    # Remediation
    remediation_summary: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    console_path: str = ""

    # Lineage
    evidence_ids: list[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    assessor: str = ""

    id: str = field(default_factory=lambda: str(uuid4()))


# ---------------------------------------------------------------------------
# Assertion function signature
# ---------------------------------------------------------------------------

# Takes (finding_detail: dict, raw_data: dict) → (passed: bool, reasons: list[str])
AssertionFn = Callable[[dict[str, Any], dict[str, Any]], tuple[bool, list[str]]]


# ---------------------------------------------------------------------------
# Assertion Engine (Tier 1)
# ---------------------------------------------------------------------------

class AssertionEngine:
    """Registry of deterministic assertion functions.

    Assertions are registered by name and looked up when evaluating
    a finding against a control. Each assertion takes the finding detail
    and raw event data, returns (passed, failure_reasons).
    """

    def __init__(self) -> None:
        self._assertions: dict[str, AssertionFn] = {}
        self._control_assertions: dict[tuple[str, str], list[str]] = {}  # (framework, control_id) → [assertion_names]
        self._remediation: dict[str, dict[str, Any]] = {}  # assertion_name → remediation info

    def register(self, name: str, fn: AssertionFn) -> None:
        """Register an assertion function."""
        self._assertions[name] = fn

    def assertion(self, name: str):
        """Decorator to register an assertion function."""
        def decorator(fn: AssertionFn) -> AssertionFn:
            self.register(name, fn)
            return fn
        return decorator

    def bind_control(self, framework: str, control_id: str, assertion_name: str) -> None:
        """Bind a control to an assertion. When this control is assessed, run this assertion.

        Multiple assertions can be bound to the same control; each call appends
        to the list rather than overwriting.
        """
        key = (framework, control_id)
        if key not in self._control_assertions:
            self._control_assertions[key] = []
        if assertion_name not in self._control_assertions[key]:
            self._control_assertions[key].append(assertion_name)

    def set_remediation(self, assertion_name: str, remediation: dict[str, Any]) -> None:
        """Set remediation info for an assertion (summary, steps, console_path)."""
        self._remediation[assertion_name] = remediation

    def get_assertion_for_control(self, framework: str, control_id: str) -> list[str] | None:
        """Return the list of assertion names bound to a control, or None."""
        assertions = self._control_assertions.get((framework, control_id))
        if assertions:
            return list(assertions)
        return None

    def evaluate(
        self,
        assertion_name: str,
        finding_detail: dict[str, Any],
        raw_data: dict[str, Any],
    ) -> tuple[bool, list[str]]:
        """Run an assertion. Returns (passed, reasons)."""
        fn = self._assertions.get(assertion_name)
        if fn is None:
            return False, [f"Unknown assertion: {assertion_name}"]
        try:
            return fn(finding_detail, raw_data)
        except Exception as e:
            log.exception("Assertion %s raised an exception", assertion_name)
            return False, [f"Assertion error: {e}"]


# ---------------------------------------------------------------------------
# Assessor — orchestrates Tier 1 + Tier 2
# ---------------------------------------------------------------------------

class Assessor:
    """Evaluates mapped findings against controls.

    Tier 1: Run deterministic assertions where available.
    Tier 2: (Future) AI reasoning for controls without assertions or
            when Tier 1 result is uncertain.
    """

    def __init__(self, engine: AssertionEngine, ai_reasoner: AIReasoner | None = None) -> None:
        self.engine = engine
        self.ai_reasoner = ai_reasoner

    def assess(
        self,
        mapped_finding: MappedFinding,
        raw_data: dict[str, Any] | None = None,
    ) -> list[ControlResultData]:
        """Assess a finding against all its mapped controls."""
        results: list[ControlResultData] = []
        finding = mapped_finding.finding
        raw = raw_data or {}

        for mapping in mapped_finding.mappings:
            result = self._assess_one(finding, mapping, raw)
            results.append(result)

        return results

    def _assess_one(
        self,
        finding: FindingData,
        mapping: ControlMappingData,
        raw_data: dict[str, Any],
    ) -> ControlResultData:
        result = ControlResultData(
            finding_id=finding.id,
            control_mapping_id=mapping.id,
            framework=mapping.framework,
            control_id=mapping.control_id,
            severity=finding.severity,
            evidence_ids=[finding.raw_event_id],
        )

        # Tier 1: deterministic assertions (may be multiple per control)
        assertion_names = self.engine.get_assertion_for_control(
            mapping.framework, mapping.control_id
        )
        if assertion_names:
            all_passed = True
            all_reasons: list[str] = []
            failed_assertions: list[str] = []
            ran_names: list[str] = []

            for aname in assertion_names:
                passed, reasons = self.engine.evaluate(
                    aname, finding.detail, raw_data
                )
                ran_names.append(aname)
                if not passed:
                    all_passed = False
                    failed_assertions.append(aname)
                all_reasons.extend(reasons)

            result.assertion_name = ",".join(ran_names)
            result.assertion_passed = all_passed
            result.assertion_findings = all_reasons
            # non_compliant if ANY assertion fails; compliant only if ALL pass
            result.status = "compliant" if all_passed else "non_compliant"
            result.assessor = f"assertion:{','.join(ran_names)}"

            # Attach remediation from the first failed assertion
            if not all_passed and failed_assertions:
                remediation = self.engine._remediation.get(failed_assertions[0], {})
                result.remediation_summary = remediation.get("summary", "")
                result.remediation_steps = remediation.get("steps", [])
                result.console_path = remediation.get("console_path", "")
        else:
            # No assertion available — mark for potential Tier 2
            result.status = "not_assessed"
            result.assessor = "none"

        # Tier 2: AI reasoning
        if result.status == "not_assessed" and self.ai_reasoner:
            try:
                ai_result = self.ai_reasoner.evaluate(finding, mapping, raw_data)
                result.ai_assessment = ai_result.assessment
                result.ai_confidence = ai_result.confidence
                result.ai_model = ai_result.model
                result.status = ai_result.status
                result.assessor = f"ai:{ai_result.model}"
                # Confidence floor — reject low-confidence AI assessments
                from warlock.config import get_settings
                floor = get_settings().ai_confidence_floor
                if ai_result.confidence < floor:
                    log.info(
                        "AI confidence %.2f below floor %.2f for %s/%s — keeping not_assessed",
                        ai_result.confidence, floor, mapping.framework, mapping.control_id,
                    )
                    result.status = "not_assessed"
                    result.assessor = f"ai:low_confidence:{ai_result.model}"
            except Exception:
                log.exception("Tier 2 AI reasoning failed for %s/%s", mapping.framework, mapping.control_id)

        return result

    # ------------------------------------------------------------------
    # Control Inheritance
    # ------------------------------------------------------------------

    def assess_with_inheritance(
        self,
        mapped_finding: MappedFinding,
        raw_data: dict[str, Any] | None = None,
        parent_results: dict[tuple[str, str], ControlResultData] | None = None,
    ) -> list[ControlResultData]:
        """Assess with parent->child inheritance for control enhancements.

        If a control like AC-2(3) has no assertion and no AI reasoner,
        but AC-2 (the parent) was already assessed, the child inherits
        the parent's status with reduced confidence.

        Args:
            mapped_finding: The finding with its control mappings.
            raw_data: Optional raw event data for assertion evaluation.
            parent_results: Pre-computed parent results keyed by
                ``(framework, control_id)``. If None, inheritance is skipped.

        Returns:
            List of ControlResultData, one per mapping.
        """
        results: list[ControlResultData] = []
        finding = mapped_finding.finding
        raw = raw_data or {}
        parents = parent_results or {}

        for mapping in mapped_finding.mappings:
            result = self._assess_one(finding, mapping, raw)

            # If still not_assessed after Tier 1 + Tier 2, try inheritance
            if result.status == "not_assessed" and parents:
                parent_id = _parse_parent_control(mapping.control_id)
                if parent_id is not None:
                    parent_key = (mapping.framework, parent_id)
                    parent = parents.get(parent_key)
                    if parent is not None and parent.status != "not_assessed":
                        result.status = parent.status
                        result.assessor = f"inherited:{parent_id}"
                        # Reduce confidence by 0.1 from parent
                        parent_conf = parent.ai_confidence if parent.ai_confidence is not None else 1.0
                        result.ai_confidence = max(0.0, round(parent_conf - 0.1, 2))
                        result.remediation_summary = parent.remediation_summary
                        result.remediation_steps = list(parent.remediation_steps)
                        result.console_path = parent.console_path

            results.append(result)

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches control IDs with parenthetical enhancements:
#   AC-2(3), SC-7(5), SI-4(2), etc.
_ENHANCEMENT_RE = re.compile(r"^(.+?)\(\d+\)$")


def _parse_parent_control(control_id: str) -> str | None:
    """Extract parent control ID from an enhancement.

    Examples:
        AC-2(3) -> AC-2
        SC-7(5) -> SC-7
        AC-2    -> None  (already a base control)
    """
    m = _ENHANCEMENT_RE.match(control_id)
    if m:
        return m.group(1).rstrip()
    return None


# Singleton engine
engine = AssertionEngine()
