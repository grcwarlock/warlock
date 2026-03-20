"""Loads remediation knowledge base from YAML files and attaches guidance to control results.

Provides both static KB lookups and AI-enhanced remediation guidance.
When AI is enabled, ``get_ai_remediation()`` augments static KB entries
with context-aware, environment-specific remediation steps via
``AIService.reason()``.  When AI is off or unavailable, it falls back
transparently to the static KB via ``get_remediation()``.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml
from pathlib import Path
from functools import lru_cache

log = logging.getLogger(__name__)


@lru_cache(maxsize=None)
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
    from warlock.ai import get_ai_service, AITask

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
