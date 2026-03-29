"""CLI commands for Business Continuity Planning (BCP) and Disaster Recovery.

Group: warlock bcp
Commands:
  systems          -- list systems with security categorization / impact tier
  bia              -- business impact analysis for systems
  dr-test schedule -- view DR test schedule
  dr-test execute  -- record a DR test result
  dr-test results  -- list DR test results
  dr-test report   -- DR test report

DR test results are stored as AuditComment records (target_type='dr_test') on
the most recent audit engagement for the system's framework, so no schema
change is required.  When no engagement exists, results are printed without
persistence and a notice is shown.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group("bcp", invoke_without_command=True)
@click.pass_context
def bcp(ctx: click.Context) -> None:
    """Business continuity planning and disaster recovery testing."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IMPACT_ORDER = {"high": 3, "moderate": 2, "medium": 2, "low": 1, "": 0}


def _impact_style(impact: str | None) -> str:
    v = (impact or "").lower()
    return {"high": "red", "moderate": "yellow", "medium": "yellow", "low": "green"}.get(v, "dim")


# ---------------------------------------------------------------------------
# list (alias for systems — CLI UX consistency)
# ---------------------------------------------------------------------------


@bcp.command("list")
@click.option(
    "--criticality",
    "-c",
    default=None,
    type=click.Choice(["high", "moderate", "low"]),
    help="Filter by overall_impact level",
)
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
@click.pass_context
def bcp_list(ctx: click.Context, criticality: str | None, output_format: str) -> None:
    """List BCP systems (alias for 'bcp systems')."""
    ctx.invoke(bcp_systems, criticality=criticality, output_format=output_format)


# ---------------------------------------------------------------------------
# systems
# ---------------------------------------------------------------------------


@bcp.command("systems")
@click.option(
    "--criticality",
    "-c",
    default=None,
    type=click.Choice(["high", "moderate", "low"]),
    help="Filter by overall_impact level",
)
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def bcp_systems(criticality: str | None, output_format: str) -> None:
    """List systems with their security impact / criticality tier.

    Criticality is derived from the FIPS 199 overall_impact field on
    SystemProfile (high / moderate / low).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile

    init_db()
    with get_session() as session:
        q = session.query(SystemProfile).filter(SystemProfile.is_active == True)  # noqa: E712
        if criticality:
            q = q.filter(SystemProfile.overall_impact.ilike(criticality))
        rows = q.order_by(SystemProfile.name).all()

        data = [
            {
                "id": r.id,
                "name": r.name,
                "acronym": r.acronym or "",
                "overall_impact": r.overall_impact or "unknown",
                "confidentiality_impact": r.confidentiality_impact or "",
                "integrity_impact": r.integrity_impact or "",
                "availability_impact": r.availability_impact or "",
                "deployment_model": r.deployment_model or "",
                "authorization_status": r.authorization_status or "",
                "system_owner": r.system_owner or "",
                "frameworks": ", ".join(r.frameworks or []),
            }
            for r in rows
        ]

    if not data:
        console.print("[dim]No systems found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Systems ({len(data)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", max_width=30)
    table.add_column("Acronym")
    table.add_column("Criticality")
    table.add_column("C / I / A")
    table.add_column("Deployment")
    table.add_column("Auth Status", max_width=15)
    table.add_column("Owner", max_width=20)

    for r in data:
        impact = r["overall_impact"]
        style = _impact_style(impact)
        cia = f"{r['confidentiality_impact'][:1].upper()}/{r['integrity_impact'][:1].upper()}/{r['availability_impact'][:1].upper()}"
        table.add_row(
            r["id"][:8],
            r["name"][:30],
            r["acronym"],
            f"[{style}]{impact}[/]",
            cia,
            r["deployment_model"] or "\u2014",
            r["authorization_status"][:15],
            r["system_owner"][:20] if r["system_owner"] else "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# bia
# ---------------------------------------------------------------------------


@bcp.command("bia")
@click.option("--system", "-s", default=None, help="System profile ID, acronym, or name fragment")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def bia(system: str | None, output_format: str) -> None:
    """Business impact analysis for systems.

    Displays FIPS 199 security categorization, authorization status,
    connected frameworks, and continuous monitoring plan summary.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile
    from warlock.cli import _resolve_system_id

    init_db()
    with get_session() as session:
        if system:
            sys_id = _resolve_system_id(session, system)
            q = session.query(SystemProfile).filter(SystemProfile.id == sys_id)
            rows = q.all()
            if not rows:
                # Fallback: name-based search
                rows = (
                    session.query(SystemProfile)
                    .filter(SystemProfile.name.ilike(f"%{system}%"))
                    .all()
                )
        else:
            rows = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .all()
            )

        data = [
            {
                "id": r.id,
                "name": r.name,
                "acronym": r.acronym or "",
                "overall_impact": r.overall_impact or "unknown",
                "confidentiality_impact": r.confidentiality_impact or "",
                "integrity_impact": r.integrity_impact or "",
                "availability_impact": r.availability_impact or "",
                "authorization_status": r.authorization_status or "",
                "authorization_date": str(r.authorization_date)[:10]
                if r.authorization_date
                else "\u2014",
                "authorization_expiry": str(r.authorization_expiry)[:10]
                if r.authorization_expiry
                else "\u2014",
                "frameworks": r.frameworks or [],
                "deployment_model": r.deployment_model or "",
                "service_model": r.service_model or "",
                "continuous_monitoring_plan": (r.continuous_monitoring_plan or "")[:120],
                "system_owner": r.system_owner or "",
                "isso": r.isso or "",
                "issm": r.issm or "",
            }
            for r in rows
        ]

    if not data:
        console.print("[dim]No systems found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    for r in data:
        from rich.panel import Panel

        impact = r["overall_impact"]
        style = _impact_style(impact)
        auth_exp_str = (
            f"  Expires:    {r['authorization_expiry']}\n"
            if r["authorization_expiry"] != "\u2014"
            else ""
        )
        console.print(
            Panel(
                f"[bold]{r['name']}[/bold]"
                + (f" ({r['acronym']})" if r["acronym"] else "")
                + f"\n\n"
                f"[bold]Security Categorization (FIPS 199):[/bold]\n"
                f"  Overall:         [{style}]{impact.upper()}[/]\n"
                f"  Confidentiality: {r['confidentiality_impact']}\n"
                f"  Integrity:       {r['integrity_impact']}\n"
                f"  Availability:    {r['availability_impact']}\n\n"
                f"[bold]Authorization:[/bold]\n"
                f"  Status:     {r['authorization_status']}\n"
                f"  Authorized: {r['authorization_date']}\n"
                + auth_exp_str
                + f"\n[bold]Deployment:[/bold] {r['deployment_model']} / {r['service_model']}\n"
                f"[bold]Frameworks:[/bold] {', '.join(r['frameworks']) or 'none'}\n\n"
                f"[bold]Responsible Parties:[/bold]\n"
                f"  Owner: {r['system_owner'] or '\u2014'}  "
                f"| ISSO: {r['isso'] or '\u2014'}  "
                f"| ISSM: {r['issm'] or '\u2014'}\n"
                + (
                    f"\n[bold]Continuous Monitoring:[/bold]\n  {r['continuous_monitoring_plan']}"
                    if r["continuous_monitoring_plan"]
                    else ""
                ),
                title=f"[bold cyan]BIA: {r['id'][:8]}[/bold cyan]",
                border_style="cyan",
            )
        )
        console.print()


# ---------------------------------------------------------------------------
# dr-test sub-group
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# backup-status (DLA-5)
# ---------------------------------------------------------------------------


@bcp.command("backup-status")
@click.option("--system", "-s", default=None, help="Filter by system name, acronym, or ID")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def bcp_backup_status(system: str | None, output_format: str) -> None:
    """Show backup status across systems.

    Queries SystemProfile records for backup-related metadata stored in
    the continuous_monitoring_plan and extra fields.  Systems are flagged
    if no backup evidence is found.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile
    from warlock.cli import _resolve_system_id

    init_db()
    with get_session() as session:
        if system:
            sys_id = _resolve_system_id(session, system)
            q = session.query(SystemProfile).filter(SystemProfile.id == sys_id)
            rows = q.all()
            if not rows:
                rows = (
                    session.query(SystemProfile)
                    .filter(SystemProfile.name.ilike(f"%{system}%"))
                    .all()
                )
        else:
            rows = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .all()
            )

        data = []
        for r in rows:
            extra = r.extra or {} if hasattr(r, "extra") else {}
            backup_info = extra.get("backup", {}) if isinstance(extra, dict) else {}
            has_conmon = bool(r.continuous_monitoring_plan)
            data.append(
                {
                    "id": r.id,
                    "name": r.name,
                    "acronym": r.acronym or "",
                    "overall_impact": r.overall_impact or "unknown",
                    "backup_frequency": backup_info.get("frequency", "not configured"),
                    "backup_location": backup_info.get("location", "not configured"),
                    "last_backup": backup_info.get("last_backup", "unknown"),
                    "backup_verified": backup_info.get("verified", False),
                    "has_conmon": has_conmon,
                }
            )

    if not data:
        console.print("[dim]No systems found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Backup Status ({len(data)} systems)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("System", max_width=30)
    table.add_column("Criticality")
    table.add_column("Backup Frequency")
    table.add_column("Location")
    table.add_column("Last Backup")
    table.add_column("Verified")
    table.add_column("ConMon Plan")

    for r in data:
        impact_style = _impact_style(r["overall_impact"])
        verified_str = "[green]Yes[/green]" if r["backup_verified"] else "[red]No[/red]"
        conmon_str = "[green]Yes[/green]" if r["has_conmon"] else "[yellow]No[/yellow]"
        table.add_row(
            r["id"][:8],
            escape(r["name"][:30]),
            f"[{impact_style}]{r['overall_impact']}[/]",
            r["backup_frequency"],
            r["backup_location"],
            r["last_backup"],
            verified_str,
            conmon_str,
        )

    console.print(table)
    not_configured = sum(1 for r in data if r["backup_frequency"] == "not configured")
    if not_configured:
        console.print(
            f"\n[yellow]Warning: {not_configured} system(s) have no backup "
            f"configuration metadata.[/yellow]"
        )


# ---------------------------------------------------------------------------
# dr-readiness (DLA-5)
# ---------------------------------------------------------------------------


@bcp.command("dr-readiness")
@click.option("--system", "-s", default=None, help="Filter by system name, acronym, or ID")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def bcp_dr_readiness(system: str | None, output_format: str) -> None:
    """DR readiness assessment — check RTO/RPO compliance across systems.

    Evaluates each system's disaster recovery readiness based on:
    - Whether DR tests have been performed
    - Whether backup configuration exists
    - Whether continuous monitoring is active
    - Criticality-based assessment thresholds
    """
    import json as _json
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditComment, SystemProfile

    _readiness_thresholds = {
        "high": {"max_days_since_test": 90, "label": "quarterly"},
        "moderate": {"max_days_since_test": 180, "label": "semi-annual"},
        "medium": {"max_days_since_test": 180, "label": "semi-annual"},
        "low": {"max_days_since_test": 365, "label": "annual"},
    }

    init_db()
    with get_session() as session:
        if system:
            from warlock.cli import _resolve_system_id

            sys_id = _resolve_system_id(session, system)
            systems = session.query(SystemProfile).filter(SystemProfile.id == sys_id).all()
            if not systems:
                systems = (
                    session.query(SystemProfile)
                    .filter(SystemProfile.name.ilike(f"%{system}%"))
                    .all()
                )
        else:
            systems = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .all()
            )

        # Get latest DR test per system
        dr_comments = (
            session.query(AuditComment)
            .filter(AuditComment.target_type == "dr_test")
            .order_by(AuditComment.created_at.desc())
            .all()
        )
        latest_tests: dict[str, dict] = {}
        for c in dr_comments:
            if c.target_id not in latest_tests:
                try:
                    payload = _json.loads(c.content)
                except (ValueError, TypeError):
                    payload = {}
                latest_tests[c.target_id] = {
                    "test_result": payload.get("test_result", "unknown"),
                    "tested_at": payload.get("tested_at", str(c.created_at))[:10],
                    "rto_actual_minutes": payload.get("rto_actual_minutes"),
                }

        data = []
        for sp in systems:
            impact = (sp.overall_impact or "low").lower()
            threshold = _readiness_thresholds.get(impact, _readiness_thresholds["low"])
            has_conmon = bool(sp.continuous_monitoring_plan)
            test_info = latest_tests.get(sp.id)

            # Readiness scoring
            score = 0
            issues: list[str] = []

            if has_conmon:
                score += 25
            else:
                issues.append("No continuous monitoring plan")

            if test_info:
                score += 25
                if test_info["test_result"] == "pass":
                    score += 25
                elif test_info["test_result"] == "partial":
                    score += 10
                    issues.append("Last DR test was partial")
                else:
                    issues.append("Last DR test failed")
            else:
                issues.append("No DR test recorded")

            # Backup check (extra field)
            extra = sp.extra or {} if hasattr(sp, "extra") else {}
            backup_info = extra.get("backup", {}) if isinstance(extra, dict) else {}
            if backup_info.get("frequency"):
                score += 25
            else:
                issues.append("No backup configuration")

            if score >= 75:
                readiness = "ready"
            elif score >= 50:
                readiness = "partial"
            elif score >= 25:
                readiness = "at_risk"
            else:
                readiness = "not_ready"

            data.append(
                {
                    "id": sp.id,
                    "name": sp.name,
                    "acronym": sp.acronym or "",
                    "overall_impact": sp.overall_impact or "unknown",
                    "required_cadence": threshold["label"],
                    "last_test": test_info["tested_at"] if test_info else "never",
                    "last_result": test_info["test_result"] if test_info else "n/a",
                    "readiness": readiness,
                    "score": score,
                    "issues": issues,
                }
            )

    if not data:
        console.print("[dim]No systems found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    _readiness_styles = {
        "ready": "green",
        "partial": "yellow",
        "at_risk": "red",
        "not_ready": "red bold",
    }

    table = Table(title=f"DR Readiness Assessment ({len(data)} systems)")
    table.add_column("System", max_width=25)
    table.add_column("Criticality")
    table.add_column("Required Cadence")
    table.add_column("Last Test")
    table.add_column("Last Result")
    table.add_column("Readiness")
    table.add_column("Score", justify="right")
    table.add_column("Issues", max_width=40)

    for r in data:
        impact_style = _impact_style(r["overall_impact"])
        readiness_style = _readiness_styles.get(r["readiness"], "")
        result_style = {"pass": "green", "fail": "red", "partial": "yellow"}.get(
            r["last_result"], "dim"
        )
        table.add_row(
            escape(r["name"][:25]),
            f"[{impact_style}]{r['overall_impact']}[/]",
            r["required_cadence"],
            r["last_test"],
            f"[{result_style}]{r['last_result']}[/]",
            f"[{readiness_style}]{r['readiness']}[/]",
            f"{r['score']}/100",
            escape("; ".join(r["issues"])[:40]) if r["issues"] else "[green]None[/green]",
        )

    console.print(table)

    ready_count = sum(1 for r in data if r["readiness"] == "ready")
    not_ready = sum(1 for r in data if r["readiness"] == "not_ready")
    console.print(
        f"\n[bold]Summary:[/bold] {ready_count} ready, "
        f"{len(data) - ready_count - not_ready} partial/at-risk, "
        f"{not_ready} not ready"
    )


# ---------------------------------------------------------------------------
# recovery-test (DLA-5)
# ---------------------------------------------------------------------------


@bcp.command("recovery-test")
@click.option("--system", "-s", required=True, help="System name, acronym, or ID")
@click.option(
    "--type",
    "test_type",
    required=True,
    type=click.Choice(["full", "partial", "tabletop", "walkthrough"]),
    help="Recovery test type",
)
@click.option(
    "--result",
    required=True,
    type=click.Choice(["pass", "fail", "partial"]),
    help="Test outcome",
)
@click.option("--rto-target", "rto_target", default=None, type=int, help="Target RTO (minutes)")
@click.option(
    "--rto-actual", "rto_actual", default=None, type=int, help="Actual RTO achieved (minutes)"
)
@click.option("--rpo-target", "rpo_target", default=None, type=int, help="Target RPO (minutes)")
@click.option(
    "--rpo-actual", "rpo_actual", default=None, type=int, help="Actual RPO achieved (minutes)"
)
@click.option("--notes", default="", help="Test observations and notes")
@click.option("--participants", default=None, help="Comma-separated list of participants")
def bcp_recovery_test(
    system: str,
    test_type: str,
    result: str,
    rto_target: int | None,
    rto_actual: int | None,
    rpo_target: int | None,
    rpo_actual: int | None,
    notes: str,
    participants: str | None,
) -> None:
    """Log a recovery test with detailed results.

    Records a recovery test including RTO/RPO targets vs actuals,
    test type, participants, and observations.  Results are stored
    as AuditComment records on the active audit engagement.
    """
    import json as _json
    from datetime import datetime, timezone
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditComment, AuditEngagement, SystemProfile
    from warlock.cli import _resolve_system_id

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        sys_id = _resolve_system_id(session, system)
        sp = session.query(SystemProfile).filter(SystemProfile.id == sys_id).first()
        if not sp:
            sp = (
                session.query(SystemProfile).filter(SystemProfile.name.ilike(f"%{system}%")).first()
            )
        if not sp:
            _error(
                f"System '{system}' not found. Use 'warlock bcp systems' to list available systems."
            )

        # Find active engagement
        eng = None
        if sp.frameworks:
            eng = (
                session.query(AuditEngagement)
                .filter(
                    AuditEngagement.framework.in_(sp.frameworks),
                    AuditEngagement.status == "active",
                )
                .order_by(AuditEngagement.created_at.desc())
                .first()
            )
        if not eng:
            eng = (
                session.query(AuditEngagement)
                .filter(AuditEngagement.status == "active")
                .order_by(AuditEngagement.created_at.desc())
                .first()
            )

        content_dict = {
            "system_id": sp.id,
            "system_name": sp.name,
            "test_type": test_type,
            "test_result": result,
            "rto_target_minutes": rto_target,
            "rto_actual_minutes": rto_actual,
            "rpo_target_minutes": rpo_target,
            "rpo_actual_minutes": rpo_actual,
            "rto_met": (rto_actual <= rto_target)
            if rto_actual is not None and rto_target is not None
            else None,
            "rpo_met": (rpo_actual <= rpo_target)
            if rpo_actual is not None and rpo_target is not None
            else None,
            "participants": [p.strip() for p in participants.split(",")] if participants else [],
            "notes": notes,
            "tested_by": actor,
            "tested_at": now.isoformat(),
        }
        content = _json.dumps(content_dict)

        if eng:
            comment = AuditComment(
                engagement_id=eng.id,
                target_type="dr_test",
                target_id=sp.id,
                author=actor,
                author_role="practitioner",
                content=content,
            )
            session.add(comment)
            session.flush()
            eng_label = f"engagement {eng.id[:8]} ({escape(eng.name)})"
        else:
            eng_label = None

    # Display results
    icon = {
        "pass": "[green]PASS[/green]",
        "fail": "[red]FAIL[/red]",
        "partial": "[yellow]PARTIAL[/yellow]",
    }[result]

    console.print(f"\n[bold]Recovery Test {icon}[/bold] for [cyan]{escape(sp.name)}[/cyan]")
    console.print(f"  Type: {test_type}")
    console.print(f"  Tested by: {escape(actor)} at {str(now)[:19]} UTC")

    if rto_target is not None or rto_actual is not None:
        rto_met = ""
        if rto_actual is not None and rto_target is not None:
            rto_met = (
                " [green](MET)[/green]" if rto_actual <= rto_target else " [red](MISSED)[/red]"
            )
        console.print(
            f"  RTO: target={rto_target or '?'}min, actual={rto_actual or '?'}min{rto_met}"
        )

    if rpo_target is not None or rpo_actual is not None:
        rpo_met = ""
        if rpo_actual is not None and rpo_target is not None:
            rpo_met = (
                " [green](MET)[/green]" if rpo_actual <= rpo_target else " [red](MISSED)[/red]"
            )
        console.print(
            f"  RPO: target={rpo_target or '?'}min, actual={rpo_actual or '?'}min{rpo_met}"
        )

    if participants:
        console.print(f"  Participants: {escape(participants)}")
    if notes:
        console.print(f"  Notes: {escape(notes)}")

    if eng_label:
        console.print(f"\n[green]Saved:[/green] result recorded in {eng_label}.")
    else:
        console.print(
            "\n[yellow]Warning:[/yellow] No active audit engagement found. "
            "Result was not persisted. Create an engagement first:\n"
            "  warlock audit engagement create --framework <fw> --name '<name>' "
            "--start-date YYYY-MM-DD --end-date YYYY-MM-DD"
        )


# ---------------------------------------------------------------------------
# dr-test sub-group
# ---------------------------------------------------------------------------


@bcp.group("dr-test", invoke_without_command=True)
@click.pass_context
def dr_test(ctx: click.Context) -> None:
    """Disaster recovery test scheduling and execution."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# dr-test schedule
# ---------------------------------------------------------------------------


@dr_test.command("schedule")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def dr_schedule(output_format: str) -> None:
    """View DR test schedule by system (derived from active audit engagements).

    Systems are listed with their recommended DR test cadence based on
    overall_impact level: high = quarterly, moderate = semi-annual, low = annual.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile

    _cadence_map = {
        "high": "quarterly",
        "moderate": "semi-annual",
        "medium": "semi-annual",
        "low": "annual",
    }

    init_db()
    with get_session() as session:
        rows = (
            session.query(SystemProfile)
            .filter(SystemProfile.is_active == True)  # noqa: E712
            .order_by(SystemProfile.name)
            .all()
        )
        data = [
            {
                "id": r.id,
                "name": r.name,
                "acronym": r.acronym or "",
                "overall_impact": r.overall_impact or "unknown",
                "recommended_cadence": _cadence_map.get((r.overall_impact or "").lower(), "annual"),
                "authorization_status": r.authorization_status or "",
                "frameworks": ", ".join(r.frameworks or [])[:40],
            }
            for r in rows
        ]

    if not data:
        console.print("[dim]No systems found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title="DR Test Schedule")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("System", max_width=30)
    table.add_column("Acronym")
    table.add_column("Criticality")
    table.add_column("Recommended Cadence")
    table.add_column("Auth Status", max_width=15)

    for r in data:
        style = _impact_style(r["overall_impact"])
        table.add_row(
            r["id"][:8],
            r["name"][:30],
            r["acronym"],
            f"[{style}]{r['overall_impact']}[/]",
            r["recommended_cadence"],
            r["authorization_status"][:15],
        )

    console.print(table)
    console.print(
        "\n[dim]Tip: record a test with 'warlock bcp dr-test execute --system <name> ...'[/dim]"
    )


# ---------------------------------------------------------------------------
# dr-test execute
# ---------------------------------------------------------------------------


@dr_test.command("execute")
@click.option("--system", "-s", required=True, help="System name, acronym, or ID")
@click.option(
    "--result",
    required=True,
    type=click.Choice(["pass", "fail", "partial"]),
    help="Test outcome",
)
@click.option(
    "--rto-actual",
    "rto_actual",
    default=None,
    type=int,
    help="Actual recovery time achieved (minutes)",
)
@click.option("--notes", default="", help="Test notes or observations")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def dr_execute(
    system: str,
    result: str,
    rto_actual: int | None,
    notes: str,
    actor: str | None,
) -> None:
    """Record a DR test result for a system.

    Results are stored as AuditComment records (target_type='dr_test') on
    the most recent active audit engagement.  If no engagement exists the
    result is shown but not persisted; create an engagement first with
    'warlock audit engagement create'.
    """
    import json as _json
    import os
    from datetime import datetime, timezone
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, AuditComment, SystemProfile
    from warlock.cli import _resolve_system_id

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor
    actor_id = actor or _get_actor()
    now = datetime.now(timezone.utc)

    init_db()
    with get_session() as session:
        sys_id = _resolve_system_id(session, system)
        sp = session.query(SystemProfile).filter(SystemProfile.id == sys_id).first()
        if not sp:
            # Fallback: name search
            sp = (
                session.query(SystemProfile).filter(SystemProfile.name.ilike(f"%{system}%")).first()
            )
        if not sp:
            _error(
                f"System '{system}' not found. Use 'warlock bcp systems' to list available systems."
            )

        # Find the most recent active engagement for any framework the system uses
        eng = None
        if sp.frameworks:
            eng = (
                session.query(AuditEngagement)
                .filter(
                    AuditEngagement.framework.in_(sp.frameworks),
                    AuditEngagement.status == "active",
                )
                .order_by(AuditEngagement.created_at.desc())
                .first()
            )
        if not eng:
            eng = (
                session.query(AuditEngagement)
                .filter(AuditEngagement.status == "active")
                .order_by(AuditEngagement.created_at.desc())
                .first()
            )

        content_dict = {
            "system_id": sp.id,
            "system_name": sp.name,
            "test_result": result,
            "rto_actual_minutes": rto_actual,
            "notes": notes,
            "tested_by": actor_id,
            "tested_at": now.isoformat(),
        }
        content = _json.dumps(content_dict)

        if eng:
            comment = AuditComment(
                engagement_id=eng.id,
                target_type="dr_test",
                target_id=sp.id,
                author=actor_id,
                author_role="practitioner",
                content=content,
            )
            session.add(comment)
            comment_id = "pending"
            session.flush()
            comment_id = comment.id
            eng_label = f"engagement {eng.id[:8]} ({eng.name})"
        else:
            comment_id = None
            eng_label = None

    icon = {
        "pass": "[green]PASS[/green]",
        "fail": "[red]FAIL[/red]",
        "partial": "[yellow]PARTIAL[/yellow]",
    }[result]
    console.print(
        f"\nDR Test {icon} for system [cyan]{sp.name}[/cyan] "
        f"at {str(now)[:19]} by [cyan]{actor_id}[/cyan]."
    )
    if rto_actual is not None:
        console.print(f"  Actual RTO: {rto_actual} minutes")
    if notes:
        console.print(f"  Notes: {notes}")

    if comment_id:
        console.print(
            f"\n[green]Saved:[/green] result recorded as comment {comment_id[:8]} in {eng_label}."
        )
    else:
        console.print(
            "\n[yellow]Warning:[/yellow] No active audit engagement found. "
            "Result was not persisted. Create an engagement first:\n"
            "  warlock audit engagement create --framework <fw> --name '<name>' "
            "--start-date YYYY-MM-DD --end-date YYYY-MM-DD"
        )


# ---------------------------------------------------------------------------
# dr-test results
# ---------------------------------------------------------------------------


@dr_test.command("results")
@click.option("--system", "-s", default=None, help="Filter by system name, acronym, or ID")
@click.option("--last", "-n", default=20, help="Show last N results (default: 20)")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def dr_results(system: str | None, last: int, output_format: str) -> None:
    """List recorded DR test results."""
    import json as _json
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditComment, SystemProfile
    from warlock.cli import _resolve_system_id

    init_db()
    with get_session() as session:
        q = (
            session.query(AuditComment)
            .filter(AuditComment.target_type == "dr_test")
            .order_by(AuditComment.created_at.desc())
        )
        if system:
            sys_id = _resolve_system_id(session, system)
            sp = session.query(SystemProfile).filter(SystemProfile.id == sys_id).first()
            if sp:
                q = q.filter(AuditComment.target_id == sp.id)
            else:
                # Try name-based lookup
                sp_name = (
                    session.query(SystemProfile)
                    .filter(SystemProfile.name.ilike(f"%{system}%"))
                    .first()
                )
                if sp_name:
                    q = q.filter(AuditComment.target_id == sp_name.id)

        comments = q.limit(last).all()

        rows: list[dict] = []
        for c in comments:
            try:
                payload = _json.loads(c.content)
            except (ValueError, TypeError):
                payload = {"notes": c.content}

            rows.append(
                {
                    "id": c.id,
                    "system_name": payload.get("system_name", c.target_id[:8]),
                    "test_result": payload.get("test_result", "unknown"),
                    "rto_actual_minutes": payload.get("rto_actual_minutes"),
                    "tested_by": payload.get("tested_by", c.author),
                    "tested_at": payload.get("tested_at", str(c.created_at))[:19],
                    "notes": (payload.get("notes") or "")[:60],
                    "engagement_id": c.engagement_id[:8],
                }
            )

    if not rows:
        console.print("[dim]No DR test results found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(rows, indent=2))
        return

    table = Table(title=f"DR Test Results (last {last})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("System", max_width=25)
    table.add_column("Result")
    table.add_column("RTO Actual (min)", justify="right")
    table.add_column("Tested By", max_width=20)
    table.add_column("Tested At")
    table.add_column("Engagement", max_width=8)
    table.add_column("Notes", max_width=40)

    for r in rows:
        result_style = {
            "pass": "green",
            "fail": "red",
            "partial": "yellow",
        }.get(r["test_result"], "")
        rto_str = str(r["rto_actual_minutes"]) if r["rto_actual_minutes"] is not None else "\u2014"
        table.add_row(
            r["id"][:8],
            r["system_name"][:25],
            f"[{result_style}]{r['test_result']}[/]",
            rto_str,
            r["tested_by"][:20],
            r["tested_at"],
            r["engagement_id"],
            r["notes"][:40],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# dr-test report
# ---------------------------------------------------------------------------


@dr_test.command("report")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "md"])
)
def dr_report(output_format: str) -> None:
    """Generate a DR test compliance report across all systems."""
    import json as _json
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditComment, SystemProfile

    init_db()
    with get_session() as session:
        comments = (
            session.query(AuditComment)
            .filter(AuditComment.target_type == "dr_test")
            .order_by(AuditComment.created_at.desc())
            .all()
        )

        # Latest result per system
        latest: dict[str, dict] = {}
        for c in comments:
            try:
                payload = _json.loads(c.content)
            except (ValueError, TypeError):
                payload = {}
            sys_id = c.target_id
            if sys_id not in latest:
                latest[sys_id] = {
                    "system_id": sys_id,
                    "system_name": payload.get("system_name", sys_id[:8]),
                    "test_result": payload.get("test_result", "unknown"),
                    "rto_actual_minutes": payload.get("rto_actual_minutes"),
                    "tested_at": payload.get("tested_at", str(c.created_at))[:10],
                }

        # Enrich with system criticality
        system_ids = list(latest.keys())
        sps = (
            (session.query(SystemProfile).filter(SystemProfile.id.in_(system_ids)).all())
            if system_ids
            else []
        )
        sp_map = {sp.id: sp for sp in sps}

        # Systems with no DR tests
        all_systems = session.query(SystemProfile).filter(SystemProfile.is_active == True).all()  # noqa: E712

    untested = [sp for sp in all_systems if sp.id not in latest]

    report_rows = []
    for sys_id, row in latest.items():
        sp = sp_map.get(sys_id)
        report_rows.append(
            {
                **row,
                "overall_impact": sp.overall_impact if sp else "unknown",
            }
        )

    # Sort: high criticality first, then by system name
    report_rows.sort(
        key=lambda r: (-_IMPACT_ORDER.get((r["overall_impact"] or "").lower(), 0), r["system_name"])
    )

    total_tested = len(report_rows)
    total_pass = sum(1 for r in report_rows if r["test_result"] == "pass")
    total_fail = sum(1 for r in report_rows if r["test_result"] == "fail")
    total_partial = sum(1 for r in report_rows if r["test_result"] == "partial")
    total_untested = len(untested)

    if output_format == "json":
        import json

        out = {
            "tested_systems": report_rows,
            "untested_systems": [
                {"id": sp.id, "name": sp.name, "overall_impact": sp.overall_impact}
                for sp in untested
            ],
            "summary": {
                "total_systems": len(all_systems),
                "tested": total_tested,
                "untested": total_untested,
                "pass": total_pass,
                "fail": total_fail,
                "partial": total_partial,
            },
        }
        console.print(json.dumps(out, indent=2))
        return

    if output_format == "md":
        console.print("# DR Test Report\n")
        console.print(f"**Total Systems:** {len(all_systems)}")
        console.print(f"**Tested:** {total_tested} | **Untested:** {total_untested}")
        console.print(
            f"**Pass:** {total_pass} | **Fail:** {total_fail} | **Partial:** {total_partial}\n"
        )
        console.print("## Results\n")
        for r in report_rows:
            console.print(
                f"- **{r['system_name']}** [{r['overall_impact']}]: "
                f"{r['test_result'].upper()} on {r['tested_at']}"
                + (f", RTO: {r['rto_actual_minutes']} min" if r["rto_actual_minutes"] else "")
            )
        if untested:
            console.print("\n## Untested Systems\n")
            for sp in untested:
                console.print(f"- {escape(sp.name or '')} [{sp.overall_impact or 'unknown'}]")
        return

    # Table mode
    from rich.panel import Panel

    console.print(
        Panel(
            f"[bold]Total Systems:[/bold] {len(all_systems)}  |  "
            f"[bold]Tested:[/bold] {total_tested}  |  "
            f"[bold]Untested:[/bold] [red]{total_untested}[/red]\n"
            f"[green]Pass: {total_pass}[/green]  |  "
            f"[red]Fail: {total_fail}[/red]  |  "
            f"[yellow]Partial: {total_partial}[/yellow]",
            title="[bold]DR Test Summary[/bold]",
            border_style="cyan",
        )
    )

    if report_rows:
        table = Table(title="DR Test Results by System")
        table.add_column("System", max_width=30)
        table.add_column("Criticality")
        table.add_column("Result")
        table.add_column("RTO Actual (min)", justify="right")
        table.add_column("Last Tested")

        for r in report_rows:
            result_style = {"pass": "green", "fail": "red", "partial": "yellow"}.get(
                r["test_result"], ""
            )
            impact_style = _impact_style(r["overall_impact"])
            rto_str = (
                str(r["rto_actual_minutes"]) if r["rto_actual_minutes"] is not None else "\u2014"
            )
            table.add_row(
                escape(r["system_name"][:30]),
                f"[{impact_style}]{r['overall_impact']}[/]",
                f"[{result_style}]{r['test_result']}[/]",
                rto_str,
                r["tested_at"],
            )

        console.print(table)

    if untested:
        console.print(f"\n[yellow]Systems with no DR tests ({total_untested}):[/yellow]")
        for sp in untested:
            style = _impact_style(sp.overall_impact)
            console.print(
                f"  [{style}]{escape(sp.name or '')}[/] ([dim]{sp.overall_impact or 'unknown'}[/dim])"
            )
