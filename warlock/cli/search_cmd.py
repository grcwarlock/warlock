"""Search and UX enhancement commands.

Provides full-text search, saved filters, smart suggestions, recent items,
faceted search, command palette, and fuzzy matching across the Warlock GRC
platform.
"""

from __future__ import annotations

import difflib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_WARLOCK_DIR = Path.home() / ".warlock"
_FILTERS_DIR = _WARLOCK_DIR / "filters"
_HISTORY_FILE = _WARLOCK_DIR / "search_history.json"

# ---------------------------------------------------------------------------
# Search group
# ---------------------------------------------------------------------------


@cli.group("search", invoke_without_command=True)
@click.pass_context
def search(ctx: click.Context) -> None:
    """Search, filter, and discover across findings, controls, issues, and more."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_dirs() -> None:
    """Create ~/.warlock/filters/ if it does not exist."""
    _FILTERS_DIR.mkdir(parents=True, exist_ok=True)


def _load_history() -> list[dict]:
    """Load search history from disk."""
    if _HISTORY_FILE.exists():
        try:
            data = json.loads(_HISTORY_FILE.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_history(history: list[dict]) -> None:
    """Persist search history, keeping the most recent 200 entries."""
    _ensure_dirs()
    history = history[-200:]
    _HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def _record_search(query: str, entity_type: str | None, result_count: int) -> None:
    """Append a search event to history."""
    history = _load_history()
    history.append(
        {
            "query": query,
            "entity_type": entity_type,
            "result_count": result_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    _save_history(history)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# UX-1: full-text search
# ---------------------------------------------------------------------------


@search.command("full-text")
@click.option("--query", "-q", required=True, help="Search query string")
@click.option(
    "--entity-type",
    "-e",
    type=click.Choice(["findings", "controls", "issues", "poams", "vendors"]),
    default=None,
    help="Restrict search to a single entity type",
)
@click.option("--limit", "-n", default=50, help="Max results per entity type")
def full_text(query: str, entity_type: str | None, limit: int) -> None:
    """Full-text search across findings, controls, issues, POAMs, and vendors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, ControlResult, Finding, Issue, Vendor

    init_db()
    like_pattern = f"%{query}%"
    results: list[tuple[str, str, str, float]] = []  # (entity_type, id, title, score)

    with get_session() as session:
        # --- Findings ---
        if entity_type is None or entity_type == "findings":
            rows = (
                session.query(Finding)
                .filter(Finding.title.ilike(like_pattern))
                .order_by(Finding.ingested_at.desc())
                .limit(limit)
                .all()
            )
            for r in rows:
                # Simple relevance: exact match scores higher
                score = 1.0 if query.lower() in (r.title or "").lower() else 0.5
                results.append(("finding", r.id[:8], r.title or "", score))

        # --- Control Results ---
        if entity_type is None or entity_type == "controls":
            rows = (
                session.query(ControlResult)
                .filter(
                    (ControlResult.control_id.ilike(like_pattern))
                    | (ControlResult.remediation_summary.ilike(like_pattern))
                )
                .order_by(ControlResult.assessed_at.desc())
                .limit(limit)
                .all()
            )
            for r in rows:
                title = f"{r.framework}/{r.control_id} ({r.status})"
                score = 1.0 if query.lower() in r.control_id.lower() else 0.5
                results.append(("control_result", r.id[:8], title, score))

        # --- Issues ---
        if entity_type is None or entity_type == "issues":
            rows = (
                session.query(Issue)
                .filter((Issue.title.ilike(like_pattern)) | (Issue.description.ilike(like_pattern)))
                .order_by(Issue.created_at.desc())
                .limit(limit)
                .all()
            )
            for r in rows:
                score = 1.0 if query.lower() in (r.title or "").lower() else 0.5
                results.append(("issue", r.id[:8], r.title or "", score))

        # --- POAMs ---
        if entity_type is None or entity_type == "poams":
            rows = (
                session.query(POAM)
                .filter(POAM.weakness_description.ilike(like_pattern))
                .order_by(POAM.created_at.desc())
                .limit(limit)
                .all()
            )
            for r in rows:
                title = f"{r.framework}/{r.control_id}: {(r.weakness_description or '')[:60]}"
                score = 1.0 if query.lower() in (r.weakness_description or "").lower() else 0.5
                results.append(("poam", r.id[:8], title, score))

        # --- Vendors ---
        if entity_type is None or entity_type == "vendors":
            rows = (
                session.query(Vendor)
                .filter(Vendor.name.ilike(like_pattern))
                .order_by(Vendor.name)
                .limit(limit)
                .all()
            )
            for r in rows:
                score = 1.0 if query.lower() in r.name.lower() else 0.5
                results.append(("vendor", r.id[:8], r.name, score))

    # Sort by relevance descending
    results.sort(key=lambda x: x[3], reverse=True)

    _record_search(query, entity_type, len(results))

    if not results:
        console.print(f"[dim]No results for '{escape(query)}'.[/dim]")
        return

    table = Table(title=f"Search results for '{escape(query)}' ({len(results)})")
    table.add_column("Type", style="cyan")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title/Description")
    table.add_column("Relevance", justify="right")

    for etype, eid, title, score in results:
        table.add_row(etype, eid, escape(title[:120]), f"{score:.1f}")

    console.print(table)


# ---------------------------------------------------------------------------
# UX-3: saved filters
# ---------------------------------------------------------------------------


@search.command("save-filter")
@click.option("--name", "-n", required=True, help="Filter name (unique)")
@click.option(
    "--entity-type",
    "-e",
    required=True,
    type=click.Choice(["findings", "controls", "issues", "poams", "vendors"]),
    help="Entity type this filter applies to",
)
@click.option(
    "--filters",
    "-f",
    required=True,
    help='JSON string of filter criteria, e.g. \'{"severity": "high", "framework": "nist_800_53"}\'',
)
def save_filter(name: str, entity_type: str, filters: str) -> None:
    """Save a named filter preset for reuse."""
    _ensure_dirs()

    try:
        criteria = json.loads(filters)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON: {escape(str(exc))}[/red]")
        raise SystemExit(1)

    preset = {
        "name": name,
        "entity_type": entity_type,
        "filters": criteria,
        "created_at": _utcnow().isoformat(),
    }

    filepath = _FILTERS_DIR / f"{name}.json"
    filepath.write_text(json.dumps(preset, indent=2))
    console.print(f"[green]Filter '{escape(name)}' saved to {filepath}[/green]")


@search.command("list-filters")
def list_filters() -> None:
    """List all saved filter presets."""
    _ensure_dirs()

    files = sorted(_FILTERS_DIR.glob("*.json"))
    if not files:
        console.print(
            "[dim]No saved filters. Use 'warlock search save-filter' to create one.[/dim]"
        )
        return

    table = Table(title="Saved Filters")
    table.add_column("Name", style="cyan")
    table.add_column("Entity Type")
    table.add_column("Filters")
    table.add_column("Created", style="dim")

    for fp in files:
        try:
            data = json.loads(fp.read_text())
            table.add_row(
                escape(data.get("name", fp.stem)),
                data.get("entity_type", ""),
                escape(json.dumps(data.get("filters", {}), separators=(",", ":"))),
                data.get("created_at", ""),
            )
        except (json.JSONDecodeError, OSError):
            table.add_row(fp.stem, "[red]corrupt[/red]", "", "")

    console.print(table)


@search.command("apply-filter")
@click.argument("name")
@click.option("--limit", "-n", default=50, help="Max results")
def apply_filter(name: str, limit: int) -> None:
    """Apply a saved filter preset and display matching results."""
    _ensure_dirs()

    filepath = _FILTERS_DIR / f"{name}.json"
    if not filepath.exists():
        console.print(
            f"[red]Filter '{escape(name)}' not found. Run 'warlock search list-filters'.[/red]"
        )
        raise SystemExit(1)

    try:
        preset = json.loads(filepath.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Failed to load filter: {escape(str(exc))}[/red]")
        raise SystemExit(1)

    entity_type = preset.get("entity_type", "findings")
    criteria = preset.get("filters", {})

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, ControlResult, Finding, Issue, Vendor

    init_db()

    with get_session() as session:
        if entity_type == "findings":
            q = session.query(Finding)
            if "severity" in criteria:
                q = q.filter(Finding.severity == criteria["severity"])
            if "source" in criteria:
                q = q.filter(Finding.source == criteria["source"])
            if "observation_type" in criteria:
                q = q.filter(Finding.observation_type == criteria["observation_type"])
            rows = q.order_by(Finding.ingested_at.desc()).limit(limit).all()

            table = Table(title=f"Findings -- filter '{escape(name)}'")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Title")
            table.add_column("Severity")
            table.add_column("Source")
            for r in rows:
                table.add_row(r.id[:8], escape(r.title[:80]), r.severity, r.source)

        elif entity_type == "controls":
            q = session.query(ControlResult)
            if "framework" in criteria:
                q = q.filter(ControlResult.framework == criteria["framework"])
            if "status" in criteria:
                q = q.filter(ControlResult.status == criteria["status"])
            rows = q.order_by(ControlResult.assessed_at.desc()).limit(limit).all()

            table = Table(title=f"Control Results -- filter '{escape(name)}'")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Framework")
            table.add_column("Control")
            table.add_column("Status")
            for r in rows:
                table.add_row(r.id[:8], r.framework, r.control_id, r.status)

        elif entity_type == "issues":
            q = session.query(Issue)
            if "status" in criteria:
                q = q.filter(Issue.status == criteria["status"])
            if "priority" in criteria:
                q = q.filter(Issue.priority == criteria["priority"])
            rows = q.order_by(Issue.created_at.desc()).limit(limit).all()

            table = Table(title=f"Issues -- filter '{escape(name)}'")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Title")
            table.add_column("Status")
            table.add_column("Priority")
            for r in rows:
                table.add_row(r.id[:8], escape((r.title or "")[:80]), r.status, r.priority)

        elif entity_type == "poams":
            q = session.query(POAM)
            if "framework" in criteria:
                q = q.filter(POAM.framework == criteria["framework"])
            if "status" in criteria:
                q = q.filter(POAM.status == criteria["status"])
            rows = q.order_by(POAM.created_at.desc()).limit(limit).all()

            table = Table(title=f"POAMs -- filter '{escape(name)}'")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Framework")
            table.add_column("Control")
            table.add_column("Status")
            for r in rows:
                table.add_row(r.id[:8], r.framework, r.control_id, r.status)

        elif entity_type == "vendors":
            q = session.query(Vendor)
            if "tier" in criteria:
                q = q.filter(Vendor.tier == criteria["tier"])
            rows = q.order_by(Vendor.name).limit(limit).all()

            table = Table(title=f"Vendors -- filter '{escape(name)}'")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Name")
            table.add_column("Tier")
            table.add_column("Risk Score")
            for r in rows:
                table.add_row(
                    r.id[:8],
                    escape(r.name),
                    r.tier or "",
                    f"{r.risk_score:.1f}" if r.risk_score else "",
                )
        else:
            console.print(f"[red]Unknown entity type: {escape(entity_type)}[/red]")
            raise SystemExit(1)

    console.print(table)


# ---------------------------------------------------------------------------
# UX-4: suggest (smart suggestions from search history)
# ---------------------------------------------------------------------------


@search.command("suggest")
@click.option("--count", "-n", default=10, help="Number of suggestions to show")
def suggest(count: int) -> None:
    """Show smart suggestions based on recent search queries."""
    history = _load_history()
    if not history:
        console.print("[dim]No search history yet. Run some searches first.[/dim]")
        return

    # Rank by frequency, then recency
    query_counts: Counter[str] = Counter()
    for entry in history:
        query_counts[entry.get("query", "")] += 1

    # Top queries by frequency
    top = query_counts.most_common(count)

    table = Table(title=f"Top {min(count, len(top))} Search Suggestions")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Query", style="cyan")
    table.add_column("Times Used", justify="right")

    for i, (q, cnt) in enumerate(top, 1):
        table.add_row(str(i), escape(q), str(cnt))

    console.print(table)

    # Also show most recent unique queries
    seen: set[str] = set()
    recent: list[str] = []
    for entry in reversed(history):
        q = entry.get("query", "")
        if q and q not in seen:
            seen.add(q)
            recent.append(q)
        if len(recent) >= 5:
            break

    if recent:
        console.print("\n[bold]Recent unique queries:[/bold]")
        for q in recent:
            console.print(f"  [dim]{escape(q)}[/dim]")


# ---------------------------------------------------------------------------
# UX-5: recent items
# ---------------------------------------------------------------------------


@search.command("recent")
@click.option("--limit", "-n", default=20, help="Number of recent items")
def recent(limit: int) -> None:
    """Show recently touched items from the audit trail."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry
    from warlock.utils import ensure_aware

    init_db()

    with get_session() as session:
        rows = session.query(AuditEntry).order_by(AuditEntry.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No recent activity found.[/dim]")
        return

    table = Table(title=f"Recent Activity (last {len(rows)} items)")
    table.add_column("When", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Entity Type")
    table.add_column("Entity ID", max_width=8, style="dim")
    table.add_column("Actor")

    for r in rows:
        created = ensure_aware(r.created_at) if r.created_at else None
        when = created.strftime("%Y-%m-%d %H:%M") if created else ""
        table.add_row(
            when,
            escape(r.action or ""),
            escape(r.entity_type or ""),
            r.entity_id[:8] if r.entity_id else "",
            escape(r.actor or ""),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# UX-6: faceted search
# ---------------------------------------------------------------------------


@search.command("faceted")
@click.option(
    "--entity-type",
    "-e",
    required=True,
    type=click.Choice(["findings", "controls", "issues", "poams", "vendors"]),
    help="Entity type to facet",
)
def faceted(entity_type: str) -> None:
    """Show faceted counts for an entity type (severity, status, framework, source)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, ControlResult, Finding, Issue, Vendor

    init_db()

    with get_session() as session:
        if entity_type == "findings":
            _print_facet(session, Finding, "severity", Finding.severity, "Findings by Severity")
            _print_facet(session, Finding, "source", Finding.source, "Findings by Source")
            _print_facet(
                session,
                Finding,
                "observation_type",
                Finding.observation_type,
                "Findings by Observation Type",
            )

        elif entity_type == "controls":
            _print_facet(
                session, ControlResult, "status", ControlResult.status, "Controls by Status"
            )
            _print_facet(
                session,
                ControlResult,
                "framework",
                ControlResult.framework,
                "Controls by Framework",
            )
            _print_facet(
                session,
                ControlResult,
                "severity",
                ControlResult.severity,
                "Controls by Severity",
            )

        elif entity_type == "issues":
            _print_facet(session, Issue, "status", Issue.status, "Issues by Status")
            _print_facet(session, Issue, "priority", Issue.priority, "Issues by Priority")

        elif entity_type == "poams":
            _print_facet(session, POAM, "status", POAM.status, "POAMs by Status")
            _print_facet(session, POAM, "framework", POAM.framework, "POAMs by Framework")
            _print_facet(session, POAM, "severity", POAM.severity, "POAMs by Severity")

        elif entity_type == "vendors":
            _print_facet(session, Vendor, "tier", Vendor.tier, "Vendors by Tier")


def _print_facet(session, model, facet_name: str, column, title: str) -> None:
    """Query and print a single facet as a Rich table."""
    from sqlalchemy import func

    rows = (
        session.query(column, func.count(column))
        .group_by(column)
        .order_by(func.count(column).desc())
        .all()
    )

    if not rows:
        console.print(f"[dim]No data for facet '{facet_name}'.[/dim]")
        return

    table = Table(title=title)
    table.add_column(facet_name.replace("_", " ").title(), style="cyan")
    table.add_column("Count", justify="right")

    for value, count in rows:
        table.add_row(escape(str(value or "null")), str(count))

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# UX-7: command palette
# ---------------------------------------------------------------------------

# Known commands with descriptions -- updated as needed.
# This list covers the major groups and subcommands. The palette command
# also introspects the Click tree at runtime for completeness.

_KNOWN_COMMANDS: list[tuple[str, str]] = [
    ("warlock pipeline init", "Initialize database and run migrations"),
    ("warlock pipeline collect", "Run all connectors and collect data"),
    ("warlock pipeline run", "Execute full pipeline (collect, normalize, map, assess)"),
    ("warlock findings list", "List normalized findings"),
    ("warlock findings search", "Search findings by keyword"),
    ("warlock findings suppress", "Suppress a finding"),
    ("warlock control list", "List control results"),
    ("warlock control summary", "Control compliance summary by framework"),
    ("warlock issues list", "List remediation issues"),
    ("warlock issues create", "Create a new issue"),
    ("warlock poam list", "List POAMs"),
    ("warlock poam create", "Create a new POA&M entry"),
    ("warlock vendors", "List vendors and risk scores"),
    ("warlock vendor-mgmt list", "List all vendors"),
    ("warlock vendor-mgmt assess", "Assess a vendor"),
    ("warlock reports executive", "Generate executive summary report"),
    ("warlock reports compliance", "Generate compliance report"),
    ("warlock dashboard posture", "View compliance posture dashboard"),
    ("warlock dashboard executive", "Executive risk dashboard"),
    ("warlock comply readiness-score", "Check framework readiness"),
    ("warlock correlate gap-analysis", "Identify compliance gaps"),
    ("warlock evidence list", "List collected evidence"),
    ("warlock audit-trail list", "View audit trail entries"),
    ("warlock audit-trail verify", "Verify hash chain integrity"),
    ("warlock oscal ssp", "Generate OSCAL SSP"),
    ("warlock oscal assessment-results", "Export OSCAL assessment results"),
    ("warlock search full-text", "Full-text search across all entities"),
    ("warlock search faceted", "Faceted search with dynamic counts"),
    ("warlock search suggest", "Smart suggestions from search history"),
    ("warlock search recent", "Recent activity from audit trail"),
    ("warlock search save-filter", "Save a named filter preset"),
    ("warlock search list-filters", "List saved filter presets"),
    ("warlock search apply-filter", "Apply a saved filter"),
    ("warlock search fuzzy", "Fuzzy match commands and entities"),
    ("warlock search palette", "List all available commands"),
    ("warlock ai configure", "Configure AI service"),
    ("warlock ai chat", "Chat with AI about compliance"),
    ("warlock alerts list", "List active alerts"),
    ("warlock remediation list", "List remediation items"),
    ("warlock terraform validate", "Validate Terraform modules"),
    ("warlock policies-opa check", "Check OPA policies"),
    ("warlock frameworks list", "List loaded frameworks"),
    ("warlock connectors list", "List available connectors"),
    ("warlock connectors status", "Show connector run status"),
    ("warlock assertions list", "List assertion definitions"),
    ("warlock risk engine run", "Run risk quantification engine"),
    ("warlock bulk import", "Bulk import data"),
    ("warlock privacy dsar", "DSAR management"),
    ("warlock incidents list", "List security incidents"),
    ("warlock incidents create", "Create an incident"),
    ("warlock calendar upcoming", "Upcoming compliance calendar events"),
    ("warlock help-topic", "Show workflow guides for common tasks"),
]


@search.command("palette")
@click.option("--filter", "-f", "filter_text", default=None, help="Filter commands by keyword")
def palette(filter_text: str | None) -> None:
    """Global command palette -- list all available warlock CLI commands."""
    # Also introspect the Click tree
    from warlock.cli import cli as root_cli

    runtime_cmds = _collect_click_commands(root_cli, prefix="warlock")

    # Merge runtime commands with known commands (runtime takes precedence for names)
    seen: set[str] = set()
    combined: list[tuple[str, str]] = []
    for name, desc in runtime_cmds:
        seen.add(name)
        combined.append((name, desc))
    for name, desc in _KNOWN_COMMANDS:
        if name not in seen:
            combined.append((name, desc))

    combined.sort(key=lambda x: x[0])

    if filter_text:
        kw = filter_text.lower()
        combined = [(n, d) for n, d in combined if kw in n.lower() or kw in d.lower()]

    if not combined:
        console.print(f"[dim]No commands matching '{escape(filter_text or '')}'.[/dim]")
        return

    table = Table(title=f"Command Palette ({len(combined)} commands)")
    table.add_column("Command", style="cyan")
    table.add_column("Description")

    for name, desc in combined:
        table.add_row(name, escape(desc))

    console.print(table)


def _collect_click_commands(group, prefix: str) -> list[tuple[str, str]]:
    """Recursively collect all Click commands from the group tree."""
    results: list[tuple[str, str]] = []
    try:
        if hasattr(group, "list_commands"):
            ctx = click.Context(group, info_name=prefix.split()[-1])
            for name in group.list_commands(ctx):
                cmd = group.get_command(ctx, name)
                if cmd is None:
                    continue
                full_name = f"{prefix} {name}"
                desc = (
                    cmd.get_short_help_str(limit=80) if hasattr(cmd, "get_short_help_str") else ""
                )
                if isinstance(cmd, click.Group):
                    # Add the group itself
                    results.append((full_name, desc))
                    # Recurse into subcommands
                    results.extend(_collect_click_commands(cmd, full_name))
                else:
                    results.append((full_name, desc))
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# UX-8: fuzzy matching
# ---------------------------------------------------------------------------


@search.command("fuzzy")
@click.option("--query", "-q", required=True, help="Fuzzy search query")
@click.option(
    "--scope",
    "-s",
    type=click.Choice(["commands", "entities", "all"]),
    default="all",
    help="Scope of fuzzy search",
)
@click.option("--limit", "-n", default=10, help="Max results")
def fuzzy(query: str, scope: str, limit: int) -> None:
    """Fuzzy matching for commands and entity titles."""
    results: list[tuple[str, str, str]] = []  # (type, name, match_source)

    # --- Commands ---
    if scope in ("commands", "all"):
        cmd_names = [name for name, _ in _KNOWN_COMMANDS]
        # Also grab runtime commands
        from warlock.cli import cli as root_cli

        runtime = _collect_click_commands(root_cli, prefix="warlock")
        cmd_names.extend(name for name, _ in runtime)
        cmd_names = list(set(cmd_names))

        matches = difflib.get_close_matches(query, cmd_names, n=limit, cutoff=0.3)
        for m in matches:
            results.append(("command", m, "command palette"))

    # --- Entities ---
    if scope in ("entities", "all"):
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import POAM, Finding, Issue, Vendor

        init_db()
        titles: list[tuple[str, str, str]] = []  # (type, id, title)

        with get_session() as session:
            # Sample recent titles from each entity type
            for row in (
                session.query(Finding.id, Finding.title)
                .order_by(Finding.ingested_at.desc())
                .limit(200)
                .all()
            ):
                titles.append(("finding", row[0][:8], row[1] or ""))

            for row in (
                session.query(Issue.id, Issue.title)
                .order_by(Issue.created_at.desc())
                .limit(100)
                .all()
            ):
                titles.append(("issue", row[0][:8], row[1] or ""))

            for row in (
                session.query(POAM.id, POAM.weakness_description)
                .order_by(POAM.created_at.desc())
                .limit(100)
                .all()
            ):
                titles.append(("poam", row[0][:8], row[1] or ""))

            for row in session.query(Vendor.id, Vendor.name).order_by(Vendor.name).limit(100).all():
                titles.append(("vendor", row[0][:8], row[1] or ""))

        title_strs = [t[2] for t in titles]
        title_map = {t[2]: t for t in titles}

        matches = difflib.get_close_matches(query, title_strs, n=limit, cutoff=0.3)
        for m in matches:
            info = title_map.get(m)
            if info:
                results.append((info[0], f"{info[1]} -- {m[:80]}", "entity title"))

    _record_search(query, "fuzzy", len(results))

    if not results:
        console.print(f"[dim]No fuzzy matches for '{escape(query)}'.[/dim]")
        return

    table = Table(title=f"Fuzzy matches for '{escape(query)}' ({len(results)})")
    table.add_column("Type", style="cyan")
    table.add_column("Match")
    table.add_column("Source", style="dim")

    for rtype, rname, rsource in results[:limit]:
        table.add_row(rtype, escape(rname), rsource)

    console.print(table)
