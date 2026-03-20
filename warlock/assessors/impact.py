"""Compliance-as-code impact analysis.

Resolves which controls are affected when assertion modules, Rego
policies, or framework YAMLs change. Designed for CI integration.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from warlock.db.models import ControlResult

log = logging.getLogger(__name__)


@dataclass
class PredictedFlip:
    """A predicted status change from a code change."""

    framework: str
    control_id: str
    from_status: str
    to_status: str
    reason: str


@dataclass
class ImpactResult:
    """Result of analyzing changed files for compliance impact."""

    changed_files: list[str]
    affected_controls: list[dict] = field(default_factory=list)
    predicted_flips: list[PredictedFlip] = field(default_factory=list)

    @property
    def has_risk(self) -> bool:
        """True if any predicted flips go to non_compliant."""
        return any(f.to_status == "non_compliant" for f in self.predicted_flips)


class ComplianceImpactAnalyzer:
    """Analyzes code changes to predict compliance impact."""

    # Pattern to extract assertion names from Python file names
    _ASSERTION_PATTERN = re.compile(r"assertions?[/\\](\w+)\.py$")
    # Pattern to extract policy names from Rego files
    _REGO_PATTERN = re.compile(r"policies?[/\\](\w+)\.rego$")
    # Pattern to extract framework names from YAML files
    _FRAMEWORK_PATTERN = re.compile(r"frameworks?[/\\](\w+)\.ya?ml$")

    def analyze(
        self,
        session: Session,
        changed_files: list[str],
    ) -> ImpactResult:
        """Resolve which controls are affected by changed files.

        Process:
        1. Classify changed files (assertion, rego policy, framework YAML)
        2. Resolve affected assertions -> which controls they bind to
        3. Resolve changed rego policies -> which controls they evaluate
        4. For each affected control, compare current status against
           what might change

        Args:
            session: SQLAlchemy session.
            changed_files: List of changed file paths.

        Returns:
            ImpactResult with affected controls and predicted flips.
        """
        result = ImpactResult(changed_files=changed_files)

        assertion_names: set[str] = set()
        framework_names: set[str] = set()

        for fpath in changed_files:
            # Assertion modules
            m = self._ASSERTION_PATTERN.search(fpath)
            if m:
                assertion_names.add(m.group(1))
                continue

            # Rego policies — rego policy names often map to assertion names
            m = self._REGO_PATTERN.search(fpath)
            if m:
                assertion_names.add(m.group(1))
                continue

            # Framework YAMLs
            m = self._FRAMEWORK_PATTERN.search(fpath)
            if m:
                framework_names.add(m.group(1))
                continue

        # Resolve assertion names to affected controls via ControlResult
        affected_controls = self._resolve_assertions(session, assertion_names)

        # Resolve framework YAML changes to all controls in those frameworks
        for fw_name in framework_names:
            fw_controls = self._resolve_framework(session, fw_name)
            for ctrl in fw_controls:
                if ctrl not in affected_controls:
                    affected_controls.append(ctrl)

        result.affected_controls = affected_controls

        # Predict flips: controls currently compliant via changed assertions
        # could flip if assertion logic changes
        for ctrl in affected_controls:
            fw = ctrl["framework"]
            cid = ctrl["control_id"]
            current_status = ctrl.get("current_status", "unknown")

            if current_status == "compliant":
                result.predicted_flips.append(
                    PredictedFlip(
                        framework=fw,
                        control_id=cid,
                        from_status="compliant",
                        to_status="non_compliant",
                        reason=f"Assertion '{ctrl.get('assertion', 'unknown')}' was modified",
                    )
                )
            elif current_status == "non_compliant":
                result.predicted_flips.append(
                    PredictedFlip(
                        framework=fw,
                        control_id=cid,
                        from_status="non_compliant",
                        to_status="compliant",
                        reason=f"Assertion '{ctrl.get('assertion', 'unknown')}' was modified",
                    )
                )

        log.info(
            "Impact analysis: %d changed files -> %d affected controls, %d predicted flips",
            len(changed_files),
            len(result.affected_controls),
            len(result.predicted_flips),
        )
        return result

    def _resolve_assertions(
        self,
        session: Session,
        assertion_names: set[str],
    ) -> list[dict]:
        """Find controls that use the given assertion names."""
        if not assertion_names:
            return []

        controls: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for name in assertion_names:
            # Match assertion_name containing the assertion module name
            # e.g., assertion_name "mfa_check" matches file "mfa_check.py"
            results = (
                session.query(
                    ControlResult.framework,
                    ControlResult.control_id,
                    ControlResult.status,
                    ControlResult.assertion_name,
                )
                .filter(ControlResult.assertion_name.contains(name))
                .distinct()
                .all()
            )

            for fw, cid, status, aname in results:
                key = (fw, cid)
                if key not in seen:
                    seen.add(key)
                    controls.append(
                        {
                            "framework": fw,
                            "control_id": cid,
                            "current_status": status,
                            "assertion": aname,
                            "source": f"assertion:{name}",
                        }
                    )

        return controls

    def _resolve_framework(
        self,
        session: Session,
        framework_name: str,
    ) -> list[dict]:
        """Find all controls in a framework affected by YAML changes."""
        # Framework name in YAML filename may use underscores, DB may too
        results = (
            session.query(
                ControlResult.framework,
                ControlResult.control_id,
                ControlResult.status,
            )
            .filter(ControlResult.framework.contains(framework_name))
            .distinct()
            .all()
        )

        controls: list[dict] = []
        for fw, cid, status in results:
            controls.append(
                {
                    "framework": fw,
                    "control_id": cid,
                    "current_status": status,
                    "source": f"framework_yaml:{framework_name}",
                }
            )

        return controls
