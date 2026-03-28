# Warlock TUI — Design Spec

**Date:** 2026-03-28
**Status:** Draft
**Vibe:** Arcane Elegance (purple-accented dark theme, keyboard-first)

## Overview

A full interactive TUI for Warlock built with Textual, replacing the default CLI entry point. Remediation is the primary dashboard — you open Warlock and immediately see what needs fixing, with actionable drill-ins that show impacted systems and copy-pasteable CLI remediation commands.

The existing 120+ Click commands remain available for scripting via `warlock --cli <command>` or automatic detection of non-TTY environments (piping, CI).

## Architecture

### Hybrid Data Access (Option C)

- **Direct SQLAlchemy** for all reads and simple writes — zero latency, no API server required
- **API client** for heavy operations (pipeline runs, AI reasoning, OSCAL exports) when the FastAPI server is running
- **Graceful fallback** — TUI works fully offline for browsing/triaging. Operations requiring the API show a clear "start API with `warlock serve`" message

### Entry Point Behavior

```
warlock              → launches TUI (when TTY detected)
warlock --cli ...    → traditional Click CLI
echo | warlock ...   → Click CLI (non-TTY auto-detected)
warlock serve        → starts FastAPI server (for API-dependent TUI features)
```

Detection: `sys.stdout.isatty()` and absence of `--cli` flag.

### Process Model

Single Python process. Textual app runs the event loop. DB sessions use the existing `get_session()` / `get_read_session()` context managers. Worker threads for background data loading (Textual's `run_worker()`).

## Visual Design

### Theme: Arcane Elegance

- **Background:** `#08081a` (deep navy-black)
- **Surface:** `#0c0c20` (slightly lighter, for panels/headers)
- **Border:** `#1e1e3a` (subtle blue-purple tint)
- **Text primary:** `#e0e0e0`
- **Text secondary:** `#888888`
- **Text muted:** `#555555`
- **Accent:** `#a78bfa` (purple — the warlock identity)
- **Status colors:**
  - Critical: `#ef4444` (red)
  - High: `#f59e0b` (amber)
  - Medium: `#eab308` (yellow)
  - Low: `#555555` (dim)
  - Compliant/closed: `#22c55e` (green)
  - In-progress: `#3b82f6` (blue)
  - Verification: `#8b5cf6` (violet)
- **Selection:** `rgba(167,139,250,0.08)` background + `2px solid #a78bfa` left border
- **Logo:** Diamond glyph `◆` in accent purple

### Typography

Inherits terminal font (typically JetBrains Mono, Fira Code, or system mono). All sizing controlled by Textual CSS relative units.

## Layout

Three-panel layout, responsive to terminal width.

```
┌──────┬────────────────────────────┬───────────────────┐
│      │ Header: title + counts     │                   │
│ Side │ Filter bar                 │   Detail Pane     │
│ bar  │                            │                   │
│      │ Scrollable list            │   (selected item  │
│ Nav  │  ► selected row            │    metadata,      │
│      │    row                     │    systems,       │
│      │    row                     │    commands,      │
│      │    row                     │    controls,      │
│      │    ...                     │    timeline)      │
│      │                            │                   │
│      ├────────────────────────────┤                   │
│      │ Footer: keyboard hints     │                   │
└──────┴────────────────────────────┴───────────────────┘
```

### Left Sidebar (52px fixed)

Persistent icon navigation. Each entry shows an icon + abbreviated label.

| Icon | Label | Screen | Keyboard |
|------|-------|--------|----------|
| ◆ | (logo) | — | — |
| ⚙ | Remed | Remediations (home) | `1` |
| ⚠ | Finds | Findings explorer | `2` |
| ■ | Ctrls | Controls by framework | `3` |
| ☰ | POA&M | POA&M tracker | `4` |
| ▲ | Pipe | Pipeline monitor | `5` |
| ★ | Frmwk | Framework overview | `6` |
| ◆ | Vendor | Vendor risk | `7` |

Active screen: purple background tint + left border accent.
Bottom: `⌘K` (command palette) and `?` (help).

### Main List Panel (flex)

- **Header bar:** Screen title + summary badges (critical count, overdue count, closed count)
- **Filter bar:** Active filters shown as removable pills. `f` to add filter, `/` to search, `Esc` to clear
- **List rows:** Severity | Status | Title | Due/age | Assignee
- **Selected row:** Purple left border + subtle background highlight
- **Footer:** Context-sensitive keyboard hints

### Right Detail Panel (240px, expandable)

Shows context for the selected list item. On `Enter`, the detail pane expands and the list narrows to a compact view (title + severity only).

## Screens

### 1. Remediations (Home Dashboard)

The default screen. Shows all remediations sorted by: overdue first, then severity, then due date.

**List columns:** Severity | Status | Title | Due date/overdue indicator | Assignee

**Summary badges:** Critical count, overdue count, open count, closed count

**Filters:** Status, severity, assignee, framework, overdue-only

**Detail pane (on selection):**
- Metadata: severity, status, assignee, due date, created date
- Remediation step progress (checklist with done/current/pending states)
- Linked items (finding, control result, alert, POA&M) — clickable to navigate

**Detail pane (on Enter — expanded drill-in):**
- All metadata above, plus:
- **Impacted Systems** — system profiles affected by this remediation, showing: system name, environment, cloud region, ATO status, exposed endpoints/resources
- **Remediation Commands** — ordered steps with copy-pasteable CLI commands. Each step shows: status (done/current/pending), description, code block with syntax-highlighted shell commands, variable placeholders called out, copy button (`c` key). When a Terraform module exists for the fix, show it as an alternative. Commands are sourced from: the remediation_steps JSON field, the linked finding's connector type (maps to known fix patterns), and the Terraform module registry.
- **Control Impact** — table of affected controls across all frameworks with current status
- **Activity Timeline** — chronological log of status changes, assignments, evidence uploads

**Keyboard:**
- `j/k` — move selection
- `Enter` — expand detail view
- `Esc` — collapse back to list view
- `a` — assign remediation
- `t` — transition status (shows valid transitions)
- `e` — attach evidence
- `c` — copy current remediation command
- `y` — yank all commands to clipboard
- `f` — open filter
- `/` — search within list

### 2. Findings Explorer

Filterable table of all normalized findings.

**List columns:** Severity | Source | Title | Control mapping | Ingested date

**Filters:** Severity, source/connector, framework, date range, has-remediation

**Detail pane:** Finding details, raw evidence, mapped controls, linked remediation (or "Create remediation" action)

### 3. Controls View

Framework picker → control-by-control status list.

**List columns:** Control ID | Title | Status | Findings count | Evidence count

**Detail pane:** Control description, assertion results, linked findings, evidence sufficiency score

### 4. POA&M Tracker

POA&M lifecycle view with state machine visualization.

**List columns:** Control | Weakness | Status | Due date | Assignee

**Detail pane:** Milestones, cost estimate, deviation requests, linked remediations

### 5. Pipeline Monitor

Recent pipeline runs, connector health, errors.

**List columns:** Run ID | Started | Duration | Findings | Errors | Status

**Detail pane:** Per-connector results, error details, hash chain verification

### 6. Framework Overview

High-level compliance posture across all 14 frameworks.

**List:** Framework cards with posture score bar, control counts by status

**Detail pane:** Framework drill-in → controls list for selected framework

### 7. Vendor Risk

Vendor assessments and questionnaire status.

**List columns:** Vendor | Tier | Risk score | Last assessed | Questionnaire status

**Detail pane:** Assessment details, SLA compliance, findings from vendor connectors

## Command Palette (Ctrl+K)

Global overlay accessible from any screen. Fuzzy-searches across:

### Search Index

**Entities (direct DB queries):**
- Remediations — by title, CVE ID, assignee
- Findings — by source, title, severity
- Controls — by ID, framework, description
- POA&Ms — by weakness, assignee, control
- Systems — by name, acronym
- Vendors — by name, tier

**Commands (static registry):**
- All 120+ existing Click commands with descriptions
- Recent commands shown first
- Favorites/bookmarks (stored in user config)

### Behavior

- Fuzzy matching with character highlighting on matches
- Category tabs (All | Commands | Remediations | Findings | Controls | Systems) — `Tab` to cycle
- `Enter` on an entity navigates to it in the relevant screen
- `Enter` on a command runs it (output shown in a modal/panel)
- `Esc` closes the palette
- Results limited to 10 per category, 20 total

## Technical Design

### Package Structure

```
warlock/tui/
  __init__.py          # WarlockApp (main Textual Application)
  app.py               # App class, screen registration, keybindings
  theme.py             # Arcane Elegance color tokens + Textual CSS
  screens/
    __init__.py
    remediations.py    # Home screen — remediation list + detail
    findings.py        # Findings explorer
    controls.py        # Controls by framework
    poam.py            # POA&M tracker
    pipeline.py        # Pipeline monitor
    frameworks.py      # Framework overview
    vendors.py         # Vendor risk
  widgets/
    __init__.py
    sidebar.py         # Left navigation sidebar
    command_palette.py # Ctrl+K fuzzy search overlay
    detail_pane.py     # Right detail panel (shared structure)
    filter_bar.py      # Filter pill bar
    status_badge.py    # Colored severity/status badges
    code_block.py      # Syntax-highlighted, copyable command blocks
    step_list.py       # Remediation step progress checklist
    timeline.py        # Activity timeline widget
  data/
    __init__.py
    queries.py         # Direct SQLAlchemy read queries (shared)
    actions.py         # Write operations (status transitions, assignments)
    search.py          # Fuzzy search index builder + matcher
    api_client.py      # Optional FastAPI client for heavy operations
```

### Key Dependencies

- `textual>=3.0` — TUI framework (already compatible with Rich)
- No other new dependencies. Everything else (SQLAlchemy, Click, Rich) already exists.

### Data Flow

```
User input (keyboard)
  → Textual event handler
  → Screen method
  → data/queries.py (SQLAlchemy read session)
  → Widget update (reactive Textual property)
  → Render
```

For writes:
```
User action (assign, transition, add evidence)
  → Screen action handler
  → data/actions.py (SQLAlchemy write session)
  → Refresh affected widgets
  → Audit trail entry (automatic via existing model hooks)
```

For API operations:
```
User action (run pipeline, AI reasoning, OSCAL export)
  → data/api_client.py
  → HTTP to localhost:PORT (if running)
  → Or error: "Start API with `warlock serve`"
```

### Textual CSS Approach

One master `theme.tcss` file defining the Arcane Elegance theme. Screens compose widgets; widgets reference theme tokens. No inline styles.

Key Textual CSS variables:
```css
$background: #08081a;
$surface: #0c0c20;
$border: #1e1e3a;
$accent: #a78bfa;
$text: #e0e0e0;
$text-muted: #888888;
$critical: #ef4444;
$high: #f59e0b;
$medium: #eab308;
$success: #22c55e;
$info: #3b82f6;
```

### Entry Point Integration

In `warlock/cli/__init__.py`, the `cli()` function checks for TTY and `--cli` flag:

```python
def cli(ctx, ...):
    if sys.stdout.isatty() and not ctx.params.get("cli_mode"):
        from warlock.tui import WarlockApp
        app = WarlockApp()
        app.run()
        raise SystemExit(0)
    # ... existing Click behavior
```

New `--cli` flag on the root group forces traditional mode.

### Search Index

The command palette builds a search index on startup:

1. **Entity index** — queries DB for top items per category (most recent, most critical). Refreshes on screen change.
2. **Command index** — introspects Click's command tree once at startup. Static for the session.
3. **Fuzzy matching** — simple subsequence match with scoring (consecutive matches score higher). No external dependency needed.

### Remediation Command Generation

Commands in the detail drill-in come from three sources, in priority order:

1. **remediation_steps JSON** — manually authored steps stored on the Remediation model. Highest fidelity.
2. **Connector-type templates** — mapping from finding source (e.g., `aws_security_hub`, `snyk`) to known fix patterns. Stored as a static registry in `warlock/tui/data/fix_templates.py`.
3. **Terraform module lookup** — if the finding maps to a resource type that has a Terraform module in `terraform/`, suggest the IaC path as an alternative.

If no commands can be generated, the detail pane shows the remediation plan text and a prompt to add steps manually.

## What This Does NOT Include

- **No web UI** — this is terminal-only
- **No real-time streaming** — data refreshes on navigation, not via websockets
- **No AI chat in TUI** — AI features stay in the Click CLI (`warlock ai-ops`, `warlock ask`). The TUI may shell out to these.
- **No custom chart widgets** — posture scores use progress bars, not graphs. Sparklines are a future nice-to-have.
- **No mouse-first design** — mouse clicks work (Textual supports them) but keyboard is the primary input

## Success Criteria

1. `warlock` launches the TUI in under 1 second (cold start)
2. Remediation list loads and renders 500+ items without lag
3. All keyboard shortcuts work without conflicts
4. Command palette returns results in <100ms
5. Detail drill-in shows impacted systems and CLI commands for every remediation that has linked findings
6. Existing Click CLI still works via `warlock --cli` and non-TTY environments
7. `make demo` + `warlock` shows a populated, navigable dashboard
