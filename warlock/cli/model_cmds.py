"""GAP-075: CLI list/show commands for 13 uncovered DB models.

Provides simple read-only listing for models that previously had no CLI exposure.
Uses a DRY helper to avoid repetitive table-building boilerplate.
"""

from __future__ import annotations

import json as _json
from datetime import datetime

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console
from warlock.utils import ensure_aware


def _list_model(
    model_class,
    columns: list[tuple[str, str, str]],
    title: str,
    limit: int = 50,
    fmt: str = "table",
) -> None:
    """Generic model lister.

    Parameters
    ----------
    model_class: SQLAlchemy model class.
    columns: list of (attr_name, column_header, style) tuples.
    title: Table title.
    limit: Max rows to display.
    fmt: "table" or "json".
    """
    from warlock.db.engine import get_read_session, init_db

    init_db()

    with get_read_session() as session:
        rows = session.query(model_class).limit(limit).all()

    if not rows:
        console.print(f"[dim]No {title.lower()} found.[/dim]")
        return

    if fmt == "json":
        data = []
        for row in rows:
            entry = {}
            for attr, _header, _style in columns:
                val = getattr(row, attr, None)
                if isinstance(val, datetime):
                    val = val.isoformat()
                entry[attr] = val
            data.append(entry)
        console.print_json(_json.dumps(data, default=str))
        return

    table = Table(title=f"{title} ({len(rows)} shown)")
    for _attr, header, style in columns:
        table.add_column(header, style=style or None)

    for row in rows:
        cells = []
        for attr, _header, _style in columns:
            val = getattr(row, attr, None)
            if val is None:
                cells.append("[dim]-[/dim]")
            elif isinstance(val, datetime):
                cells.append(str(ensure_aware(val).strftime("%Y-%m-%d %H:%M")))
            elif isinstance(val, (list, dict)):
                cells.append(escape(str(val)[:60]))
            else:
                cells.append(escape(str(val)[:50]))
        table.add_row(*cells)

    console.print(table)


# ---------------------------------------------------------------------------
# Individual commands
# ---------------------------------------------------------------------------

_FMT_OPTION = click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
_LIMIT_OPTION = click.option("--limit", default=50, help="Max rows to show.")


@cli.command("posture-snapshots")
@_FMT_OPTION
@_LIMIT_OPTION
def posture_snapshots_cmd(fmt: str, limit: int) -> None:
    """List posture snapshots."""
    from warlock.db.models import PostureSnapshot

    _list_model(
        PostureSnapshot,
        [
            ("id", "ID", "dim"),
            ("framework", "Framework", "cyan"),
            ("control_id", "Control", ""),
            ("status", "Status", ""),
            ("posture_score", "Score", ""),
            ("snapshot_date", "Date", ""),
        ],
        "Posture Snapshots",
        limit=limit,
        fmt=fmt,
    )


@cli.command("compensating-controls")
@_FMT_OPTION
@_LIMIT_OPTION
def compensating_controls_cmd(fmt: str, limit: int) -> None:
    """List compensating controls."""
    from warlock.db.models import CompensatingControl

    _list_model(
        CompensatingControl,
        [
            ("id", "ID", "dim"),
            ("original_framework", "Framework", "cyan"),
            ("original_control_id", "Control", ""),
            ("title", "Title", ""),
            ("status", "Status", ""),
            ("effectiveness_score", "Effectiveness", ""),
        ],
        "Compensating Controls",
        limit=limit,
        fmt=fmt,
    )


@cli.command("risk-acceptances")
@_FMT_OPTION
@_LIMIT_OPTION
def risk_acceptances_cmd(fmt: str, limit: int) -> None:
    """List risk acceptances."""
    from warlock.db.models import RiskAcceptance

    _list_model(
        RiskAcceptance,
        [
            ("id", "ID", "dim"),
            ("framework", "Framework", "cyan"),
            ("control_id", "Control", ""),
            ("risk_level", "Risk Level", ""),
            ("status", "Status", ""),
            ("expiry_date", "Expires", ""),
            ("requested_by", "Requested By", ""),
        ],
        "Risk Acceptances",
        limit=limit,
        fmt=fmt,
    )


@cli.command("control-inheritances")
@_FMT_OPTION
@_LIMIT_OPTION
def control_inheritances_cmd(fmt: str, limit: int) -> None:
    """List control inheritance mappings."""
    from warlock.db.models import ControlInheritance

    _list_model(
        ControlInheritance,
        [
            ("id", "ID", "dim"),
            ("framework", "Framework", "cyan"),
            ("control_id", "Control", ""),
            ("inheritance_type", "Type", ""),
            ("status", "Status", ""),
        ],
        "Control Inheritances",
        limit=limit,
        fmt=fmt,
    )


@cli.command("system-dependencies")
@_FMT_OPTION
@_LIMIT_OPTION
def system_dependencies_cmd(fmt: str, limit: int) -> None:
    """List system dependencies."""
    from warlock.db.models import SystemDependency

    _list_model(
        SystemDependency,
        [
            ("id", "ID", "dim"),
            ("consumer_system_id", "Consumer", ""),
            ("provider_system_id", "Provider", ""),
            ("dependency_type", "Type", "cyan"),
            ("description", "Description", ""),
        ],
        "System Dependencies",
        limit=limit,
        fmt=fmt,
    )


@cli.command("change-events")
@_FMT_OPTION
@_LIMIT_OPTION
def change_events_cmd(fmt: str, limit: int) -> None:
    """List change events."""
    from warlock.db.models import ChangeEvent

    _list_model(
        ChangeEvent,
        [
            ("id", "ID", "dim"),
            ("source", "Source", "cyan"),
            ("event_type", "Event Type", ""),
            ("actor", "Actor", ""),
            ("action", "Action", ""),
            ("occurred_at", "Occurred", ""),
        ],
        "Change Events",
        limit=limit,
        fmt=fmt,
    )


@cli.command("compliance-drifts")
@_FMT_OPTION
@_LIMIT_OPTION
def compliance_drifts_cmd(fmt: str, limit: int) -> None:
    """List compliance drift records."""
    from warlock.db.models import ComplianceDrift

    _list_model(
        ComplianceDrift,
        [
            ("id", "ID", "dim"),
            ("framework", "Framework", "cyan"),
            ("control_id", "Control", ""),
            ("previous_status", "Previous", ""),
            ("new_status", "New", ""),
            ("drift_direction", "Direction", ""),
            ("detected_at", "Detected", ""),
        ],
        "Compliance Drifts",
        limit=limit,
        fmt=fmt,
    )


@cli.command("policy-overrides")
@_FMT_OPTION
@_LIMIT_OPTION
def policy_overrides_cmd(fmt: str, limit: int) -> None:
    """List OPA policy overrides."""
    from warlock.db.models import PolicyOverride

    _list_model(
        PolicyOverride,
        [
            ("id", "ID", "dim"),
            ("name", "Name", "cyan"),
            ("is_active", "Active", ""),
            ("created_by", "Created By", ""),
            ("created_at", "Created", ""),
        ],
        "Policy Overrides",
        limit=limit,
        fmt=fmt,
    )


@cli.command("external-auditors")
@_FMT_OPTION
@_LIMIT_OPTION
def external_auditors_cmd(fmt: str, limit: int) -> None:
    """List external auditors."""
    from warlock.db.models import ExternalAuditor

    _list_model(
        ExternalAuditor,
        [
            ("id", "ID", "dim"),
            ("name", "Name", "cyan"),
            ("email", "Email", ""),
            ("firm", "Firm", ""),
            ("is_active", "Active", ""),
            ("last_accessed", "Last Access", ""),
        ],
        "External Auditors",
        limit=limit,
        fmt=fmt,
    )


@cli.command("evidence-requests")
@_FMT_OPTION
@_LIMIT_OPTION
def evidence_requests_cmd(fmt: str, limit: int) -> None:
    """List evidence requests."""
    from warlock.db.models import EvidenceRequest

    _list_model(
        EvidenceRequest,
        [
            ("id", "ID", "dim"),
            ("framework", "Framework", "cyan"),
            ("control_id", "Control", ""),
            ("description", "Description", ""),
            ("status", "Status", ""),
            ("created_at", "Created", ""),
        ],
        "Evidence Requests",
        limit=limit,
        fmt=fmt,
    )


@cli.command("embeddings")
@_FMT_OPTION
@_LIMIT_OPTION
def embeddings_cmd(fmt: str, limit: int) -> None:
    """List stored embeddings."""
    from warlock.db.models import Embedding

    _list_model(
        Embedding,
        [
            ("id", "ID", "dim"),
            ("entity_type", "Entity Type", "cyan"),
            ("entity_id", "Entity ID", ""),
            ("model_name", "Model", ""),
            ("dimensions", "Dims", ""),
            ("created_at", "Created", ""),
        ],
        "Embeddings",
        limit=limit,
        fmt=fmt,
    )


@cli.command("watch-subscriptions")
@_FMT_OPTION
@_LIMIT_OPTION
def watch_subscriptions_cmd(fmt: str, limit: int) -> None:
    """List watch subscriptions."""
    from warlock.db.models import WatchSubscription

    _list_model(
        WatchSubscription,
        [
            ("id", "ID", "dim"),
            ("user_id", "User", ""),
            ("entity_type", "Entity Type", "cyan"),
            ("entity_id", "Entity ID", ""),
            ("created_at", "Created", ""),
        ],
        "Watch Subscriptions",
        limit=limit,
        fmt=fmt,
    )


@cli.command("escalation-policies")
@_FMT_OPTION
@_LIMIT_OPTION
def escalation_policies_cmd(fmt: str, limit: int) -> None:
    """List escalation policies."""
    from warlock.db.models import EscalationPolicy

    _list_model(
        EscalationPolicy,
        [
            ("id", "ID", "dim"),
            ("name", "Name", "cyan"),
            ("description", "Description", ""),
            ("active", "Active", ""),
            ("entity_types", "Entity Types", ""),
            ("min_severity", "Min Severity", ""),
        ],
        "Escalation Policies",
        limit=limit,
        fmt=fmt,
    )
