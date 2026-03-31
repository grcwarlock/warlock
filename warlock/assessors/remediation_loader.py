"""Loads remediation knowledge base from YAML files and attaches guidance to control results.

Provides both static KB lookups and AI-enhanced remediation guidance.
When AI is enabled, ``get_ai_remediation()`` augments static KB entries
with context-aware, environment-specific remediation steps via
``AIService.reason()``.  When AI is off or unavailable, it falls back
transparently to the static KB via ``get_remediation()``.
"""

from __future__ import annotations

import logging
from functools import cache
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


@cache
def load_remediation_kb(remediation_dir: str = None) -> dict:
    """Load all remediation YAML files into a single lookup.
    Returns: {(framework, control_id): remediation_dict}
    """
    if remediation_dir is None:
        remediation_dir = str(Path(__file__).resolve().parent.parent / "frameworks" / "remediation")

    kb = {}
    rem_path = Path(remediation_dir)
    if not rem_path.is_dir():
        return kb

    for yaml_file in rem_path.glob("*.yaml"):
        framework_id = yaml_file.stem
        data = yaml.safe_load(yaml_file.read_text()) or {}
        for ctrl_id, guidance in data.get("controls", {}).items():
            kb[(framework_id, ctrl_id)] = guidance

    return kb


def get_remediation(framework: str, control_id: str) -> dict | None:
    """Get remediation guidance for a specific control."""
    kb = load_remediation_kb()
    return kb.get((framework, control_id))


def enrich_control_result(result, framework: str, control_id: str):
    """Attach remediation data from the KB to a ControlResult if it has none."""
    if result.remediation_summary:
        return  # Already has remediation from assertion

    guidance = get_remediation(framework, control_id)
    if guidance:
        result.remediation_summary = guidance.get("summary", "")
        result.remediation_steps = guidance.get("remediation_steps", [])
        result.console_path = guidance.get("console_path", "")


# ---------------------------------------------------------------------------
# Crosswalk loader (cached)
# ---------------------------------------------------------------------------


@cache
def _load_crosswalks() -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Load crosswalk YAML files and build a bidirectional index.

    Returns ``{(framework, control_id): [equivalent controls ...]}``
    where each entry is a dict with ``framework``, ``control_id``, and
    ``confidence`` keys.
    """
    crosswalk_dir = Path(__file__).resolve().parent.parent / "frameworks"
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for yaml_file in sorted(crosswalk_dir.glob("crosswalk*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text()) or {}
        except Exception:
            log.warning("Failed to parse crosswalk YAML: %s", yaml_file)
            continue

        entries = data.get("crosswalks", data.get("mappings", []))
        if not isinstance(entries, list):
            continue

        for cw in entries:
            src_fw = cw.get("source_framework", "")
            src_ctrl = cw.get("source_control", "")
            tgt_fw = cw.get("target_framework", "")
            tgt_ctrl = cw.get("target_control", "")
            confidence = cw.get("confidence", 0.9)

            index.setdefault((src_fw, src_ctrl), []).append(
                {
                    "framework": tgt_fw,
                    "control_id": tgt_ctrl,
                    "confidence": confidence,
                }
            )
            # Bidirectional
            index.setdefault((tgt_fw, tgt_ctrl), []).append(
                {
                    "framework": src_fw,
                    "control_id": src_ctrl,
                    "confidence": confidence,
                }
            )

    return index


def _get_crosswalk_entries(framework: str, control_id: str) -> list[dict[str, Any]]:
    """Return crosswalk entries for a given framework/control pair."""
    return list(_load_crosswalks().get((framework, control_id), []))


# ---------------------------------------------------------------------------
# Framework YAML loader (for control descriptions)
# ---------------------------------------------------------------------------


@cache
def _load_framework_yaml(framework: str) -> dict[str, Any]:
    """Load a single framework YAML and return its raw dict."""
    fw_dir = Path(__file__).resolve().parent.parent / "frameworks"
    yaml_path = fw_dir / f"{framework}.yaml"
    if not yaml_path.is_file():
        return {}
    try:
        return yaml.safe_load(yaml_path.read_text()) or {}
    except Exception:
        log.warning("Failed to parse framework YAML: %s", yaml_path)
        return {}


def _get_control_description(framework: str, control_id: str) -> str:
    """Extract a human-readable description for a control.

    Checks the framework YAML first (some controls carry a
    ``description`` key), then falls back to the remediation KB summary.
    """
    fw_data = _load_framework_yaml(framework)
    families = fw_data.get("control_families", {})
    for _family_id, family_data in families.items():
        controls = family_data.get("controls", {})
        if control_id in controls:
            ctrl = controls[control_id]
            if isinstance(ctrl, dict) and ctrl.get("description"):
                return str(ctrl["description"])

    # Fall back to remediation KB summary
    guidance = get_remediation(framework, control_id)
    if guidance:
        return guidance.get("summary", "")
    return ""


# ---------------------------------------------------------------------------
# get_control_detail -- aggregated control view
# ---------------------------------------------------------------------------


def get_control_detail(
    session: Any,
    control_id: str,
    framework: str | None = None,
) -> dict[str, Any] | None:
    """Build a comprehensive detail dict for a control across frameworks.

    Queries ``ControlResult`` rows matching *control_id* (optionally
    filtered by *framework*), joins each with its ``Finding`` to pull
    resource-level detail, and groups results into passing/failing
    resource lists.

    Attaches KB remediation (structured), a control description (from
    framework YAML or KB summary), and crosswalk data showing equivalent
    controls in other frameworks.

    Returns ``None`` when no matching control results exist.
    """
    from warlock.db.models import ControlResult, Finding

    # Build the joined query -- single round-trip instead of N+1
    q = (
        session.query(ControlResult, Finding)
        .join(Finding, ControlResult.finding_id == Finding.id)
        .filter(ControlResult.control_id == control_id)
    )
    if framework:
        q = q.filter(ControlResult.framework == framework)

    rows = q.all()

    if not rows:
        # Retry with case-insensitive match
        q = (
            session.query(ControlResult, Finding)
            .join(Finding, ControlResult.finding_id == Finding.id)
            .filter(ControlResult.control_id.ilike(control_id))
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.all()

    if not rows:
        return None

    # Accumulate counts and resource buckets
    frameworks_seen: set[str] = set()
    passing_resources: list[dict[str, Any]] = []
    failing_resources: list[dict[str, Any]] = []
    compliant_count = 0
    non_compliant_count = 0
    partial_count = 0
    not_assessed_count = 0

    for cr, finding in rows:
        frameworks_seen.add(cr.framework)

        resource_dict: dict[str, Any] = {
            "resource_id": finding.resource_id or "unknown",
            "resource_type": finding.resource_type or "unknown",
            "source": finding.source,
            "provider": finding.provider,
            "region": finding.region or "",
            "account_id": finding.account_id or "",
            "framework": cr.framework,
            "control_id": cr.control_id,
            "severity": cr.severity,
            "finding_title": finding.title,
        }

        if cr.status == "compliant":
            compliant_count += 1
            passing_resources.append(resource_dict)
        elif cr.status == "non_compliant":
            non_compliant_count += 1
            failing_resources.append(resource_dict)
        elif cr.status == "partial":
            partial_count += 1
            failing_resources.append(resource_dict)
        elif cr.status == "not_assessed":
            not_assessed_count += 1
        # Other statuses (not_applicable, risk_accepted, inherited_*)
        # are counted in total_results but not bucketed.

    sorted_frameworks = sorted(frameworks_seen)

    # Primary framework for KB / description lookups
    primary_framework = framework or (sorted_frameworks[0] if sorted_frameworks else "")

    # -- Remediation (structured) --
    guidance = get_remediation(primary_framework, control_id) if primary_framework else None
    remediation: dict[str, Any] = {
        "summary": "",
        "steps": [],
        "console_path": "",
        "recommended_reading": [],
        "assertion_name": "",
    }
    if guidance:
        remediation["summary"] = guidance.get("summary", "")
        remediation["steps"] = guidance.get("remediation_steps", [])
        remediation["console_path"] = guidance.get("console_path", "")
        remediation["recommended_reading"] = guidance.get("recommended_reading", [])
        remediation["assertion_name"] = guidance.get("assertion_name", "")

    # -- Control description --
    description = (
        _get_control_description(primary_framework, control_id) if primary_framework else ""
    )
    if not description:
        description = remediation["summary"]

    # -- Crosswalk --
    crosswalk: list[dict[str, Any]] = []
    if primary_framework:
        crosswalk = _get_crosswalk_entries(primary_framework, control_id)

    return {
        "control_id": control_id,
        "frameworks": sorted_frameworks,
        "description": description,
        "total_results": len(rows),
        "compliant_count": compliant_count,
        "non_compliant_count": non_compliant_count,
        "partial_count": partial_count,
        "not_assessed_count": not_assessed_count,
        "passing_resources": passing_resources,
        "failing_resources": failing_resources,
        "remediation": remediation,
        "crosswalk": crosswalk,
    }


def get_ai_control_remediation(
    session: Any,
    control_id: str,
    framework: str,
    failing_resources: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Generate AI-powered, per-resource remediation commands.

    Sends the failing resource details and static KB guidance as context
    to ``AIService.reason(AITask.REMEDIATION_GUIDANCE)`` and returns
    the AI response (typically per-resource CLI commands or IaC changes).

    Falls back to ``None`` when AI is unavailable or the task is
    disabled.

    Args:
        session: A SQLAlchemy ``Session`` (reserved for future
            evidence lookups).
        control_id: The control identifier (e.g. ``"AC-2"``).
        framework: The framework to scope remediation against.
        failing_resources: List of resource dicts (as returned by
            ``get_control_detail()["failing_resources"]``).

    Returns:
        A dict with per-resource remediation commands, or ``None``
        if AI is not available.
    """
    from warlock.ai import AITask, get_ai_service

    static_guidance = get_remediation(framework, control_id)

    ai = get_ai_service()
    context: dict[str, Any] = {
        "framework": framework,
        "control_id": control_id,
        "static_kb_entry": static_guidance,
        "failing_resources": failing_resources,
        "task_instruction": (
            "For each failing resource, produce specific remediation "
            "commands (CLI, console steps, or IaC changes) that would "
            "bring it into compliance."
        ),
    }

    result = ai.reason(
        task=AITask.REMEDIATION_GUIDANCE,
        context=context,
        fallback=lambda: None,
    )

    log.debug(
        "get_ai_control_remediation %s/%s ai_used=%s",
        framework,
        control_id,
        result.ai_used,
    )

    return result.value if result.ai_used else None


def get_ai_remediation(
    framework: str,
    control_id: str,
    finding_data: dict[str, Any] | None = None,
    environment_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return AI-enhanced remediation guidance for a control finding.

    When AI is enabled and the ``REMEDIATION_GUIDANCE`` task is active,
    calls ``AIService.reason()`` with the static KB entry, finding data,
    and environment context to produce tailored, actionable remediation
    steps.

    When AI is off (no provider configured, task disabled, or API error),
    falls back transparently to the static KB entry returned by
    ``get_remediation(framework, control_id)``.

    Args:
        framework: Framework identifier (e.g. ``"nist_800_53"``).
        control_id: Control identifier (e.g. ``"AC-2"``).
        finding_data: Optional dict of finding details (resource_id,
            severity, observation data) to give the model specificity.
        environment_context: Optional dict describing the target
            environment (cloud provider, region, account, IaC tool)
            so the model can tailor remediation to the actual stack.

    Returns:
        A dict with remediation guidance.  When AI is used the dict
        is the parsed model response (typically ``guidance`` and
        ``steps`` keys).  When falling back, returns the static KB
        dict or ``None`` if no KB entry exists.
    """
    from warlock.ai import AITask, get_ai_service

    static_guidance = get_remediation(framework, control_id)

    ai = get_ai_service()
    context: dict[str, Any] = {
        "framework": framework,
        "control_id": control_id,
        "static_kb_entry": static_guidance,
        "finding_data": finding_data or {},
        "environment_context": environment_context or {},
    }

    result = ai.reason(
        task=AITask.REMEDIATION_GUIDANCE,
        context=context,
        fallback=lambda: static_guidance,
    )

    log.debug(
        "get_ai_remediation %s/%s ai_used=%s confidence=%.2f",
        framework,
        control_id,
        result.ai_used,
        result.confidence,
    )

    return result.value
