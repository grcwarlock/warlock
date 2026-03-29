"""YAML-based no-code workflow builder.

Parses workflow definitions from YAML files and executes them as
step-by-step automation sequences. Supports conditional steps,
approvals, and notification hooks.

Workflow YAML format:
    name: "quarterly-review"
    description: "Quarterly compliance review workflow"
    trigger: "schedule"
    schedule: "0 9 1 */3 *"
    steps:
      - name: "collect-evidence"
        action: "pipeline.collect"
        params:
          sources: ["aws", "azure"]
      - name: "run-assessment"
        action: "assess.framework"
        params:
          framework: "soc2"
      - name: "generate-report"
        action: "export.report"
        params:
          format: "pdf"
      - name: "notify-stakeholders"
        action: "notify.email"
        params:
          recipients: ["ciso@example.com"]
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Workflow data model
# ---------------------------------------------------------------------------


@dataclass
class WorkflowStep:
    """A single step in a workflow."""

    name: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    condition: str | None = None  # Optional condition expression
    on_failure: str = "stop"  # "stop", "continue", "retry"
    max_retries: int = 0
    timeout_seconds: int = 300


@dataclass
class WorkflowDefinition:
    """A parsed workflow definition."""

    id: str = ""
    name: str = ""
    description: str = ""
    trigger: str = "manual"  # "manual", "schedule", "event"
    schedule: str = ""
    steps: list[WorkflowStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowRun:
    """State of a workflow execution."""

    run_id: str = ""
    workflow_id: str = ""
    workflow_name: str = ""
    status: str = "pending"  # "pending", "running", "completed", "failed", "cancelled"
    started_at: str = ""
    completed_at: str = ""
    current_step: int = 0
    total_steps: int = 0
    step_results: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# In-memory workflow registry
# ---------------------------------------------------------------------------

_workflows: dict[str, WorkflowDefinition] = {}
_runs: dict[str, WorkflowRun] = {}


# ---------------------------------------------------------------------------
# Known actions (extensible)
# ---------------------------------------------------------------------------

_KNOWN_ACTIONS = {
    "pipeline.collect": "Run pipeline collection for specified sources",
    "pipeline.full": "Run full pipeline (collect -> normalize -> map -> assess)",
    "assess.framework": "Run assessment for a specific framework",
    "export.report": "Generate compliance report",
    "export.oscal": "Export OSCAL SSP/assessment results",
    "notify.email": "Send email notification (stub)",
    "notify.slack": "Send Slack notification (stub)",
    "notify.teams": "Send Teams notification (stub)",
    "approval.request": "Request approval from specified approvers",
    "poam.scan": "Scan for overdue POA&M items",
    "risk.analyze": "Run risk analysis for a framework",
    "evidence.collect": "Collect evidence for specified controls",
}


def parse_workflow(content: str) -> WorkflowDefinition:
    """Parse a workflow definition from YAML string.

    Raises ValueError if the YAML is malformed or missing required fields.
    """
    if not _HAS_YAML:
        raise RuntimeError("PyYAML required for workflow parsing: pip install pyyaml")

    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError("Workflow YAML must be a mapping at root level")

    wf = WorkflowDefinition(
        id=data.get("id", str(uuid.uuid4())[:8]),
        name=data.get("name", "unnamed"),
        description=data.get("description", ""),
        trigger=data.get("trigger", "manual"),
        schedule=data.get("schedule", ""),
        metadata=data.get("metadata", {}),
    )

    for step_data in data.get("steps", []):
        if not isinstance(step_data, dict):
            continue
        step = WorkflowStep(
            name=step_data.get("name", "unnamed-step"),
            action=step_data.get("action", ""),
            params=step_data.get("params", {}),
            condition=step_data.get("condition"),
            on_failure=step_data.get("on_failure", "stop"),
            max_retries=step_data.get("max_retries", 0),
            timeout_seconds=step_data.get("timeout_seconds", 300),
        )
        if not step.action:
            log.warning("Step '%s' has no action -- skipping", step.name)
            continue
        wf.steps.append(step)

    return wf


def load_workflow_file(path: str) -> WorkflowDefinition:
    """Load a workflow definition from a YAML file."""
    with open(path) as fh:
        content = fh.read()
    wf = parse_workflow(content)
    if not wf.id:
        wf.id = Path(path).stem
    return wf


def register_workflow(wf: WorkflowDefinition) -> None:
    """Register a workflow definition in the in-memory registry."""
    _workflows[wf.name] = wf
    log.info("Workflow registered: %s (%d steps)", wf.name, len(wf.steps))


def list_workflows() -> list[WorkflowDefinition]:
    """List all registered workflows."""
    return list(_workflows.values())


def get_workflow(name: str) -> WorkflowDefinition | None:
    """Get a workflow by name."""
    return _workflows.get(name)


def run_workflow(name: str) -> WorkflowRun:
    """Execute a registered workflow (dry-run -- logs steps without executing).

    Full action execution will be implemented when action handlers are
    wired. Currently validates the workflow and records step completion.
    """
    wf = _workflows.get(name)
    if not wf:
        raise ValueError(f"Workflow '{name}' not found. Register it first.")

    run = WorkflowRun(
        run_id=str(uuid.uuid4())[:8],
        workflow_id=wf.id,
        workflow_name=wf.name,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        total_steps=len(wf.steps),
    )
    _runs[run.run_id] = run

    for i, step in enumerate(wf.steps):
        run.current_step = i + 1
        action_desc = _KNOWN_ACTIONS.get(step.action, "Unknown action")

        step_result = {
            "step": i + 1,
            "name": step.name,
            "action": step.action,
            "description": action_desc,
            "status": "completed",
            "params": step.params,
            "note": "Dry-run -- action not executed",
        }

        if step.action not in _KNOWN_ACTIONS:
            step_result["status"] = "skipped"
            step_result["note"] = f"Unknown action: {step.action}"

        run.step_results.append(step_result)
        log.info(
            "Workflow %s step %d/%d: %s (%s) -> %s",
            name,
            i + 1,
            len(wf.steps),
            step.name,
            step.action,
            step_result["status"],
        )

    run.status = "completed"
    run.completed_at = datetime.now(timezone.utc).isoformat()
    return run
