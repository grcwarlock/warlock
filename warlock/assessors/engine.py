"""Layer 3 — Assessment.

Two-tier evaluation:
  Tier 1: Deterministic assertions (fast, auditable, reproducible)
  Tier 2: AI reasoning (optional, for when Tier 1 is insufficient)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

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
        self._control_assertions: dict[tuple[str, str], str] = {}  # (framework, control_id) → assertion_name
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
        """Bind a control to an assertion. When this control is assessed, run this assertion."""
        self._control_assertions[(framework, control_id)] = assertion_name

    def set_remediation(self, assertion_name: str, remediation: dict[str, Any]) -> None:
        """Set remediation info for an assertion (summary, steps, console_path)."""
        self._remediation[assertion_name] = remediation

    def get_assertion_for_control(self, framework: str, control_id: str) -> str | None:
        return self._control_assertions.get((framework, control_id))

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

    def __init__(self, engine: AssertionEngine, ai_reasoner: Any | None = None) -> None:
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

        # Tier 1: deterministic assertion
        assertion_name = self.engine.get_assertion_for_control(
            mapping.framework, mapping.control_id
        )
        if assertion_name:
            passed, reasons = self.engine.evaluate(
                assertion_name, finding.detail, raw_data
            )
            result.assertion_name = assertion_name
            result.assertion_passed = passed
            result.assertion_findings = reasons
            result.status = "compliant" if passed else "non_compliant"
            result.assessor = f"assertion:{assertion_name}"

            # Attach remediation on failure
            if not passed:
                remediation = self.engine._remediation.get(assertion_name, {})
                result.remediation_summary = remediation.get("summary", "")
                result.remediation_steps = remediation.get("steps", [])
                result.console_path = remediation.get("console_path", "")
        else:
            # No assertion available — mark for potential Tier 2
            result.status = "not_assessed"
            result.assessor = "none"

        # Tier 2: AI reasoning (future — plug in here)
        # if result.status == "not_assessed" and self.ai_reasoner:
        #     ai_result = self.ai_reasoner.evaluate(finding, mapping)
        #     result.ai_assessment = ai_result.assessment
        #     result.ai_confidence = ai_result.confidence
        #     result.ai_model = ai_result.model
        #     result.status = ai_result.status
        #     result.assessor = f"ai:{ai_result.model}"

        return result


# Singleton engine
engine = AssertionEngine()
