# Interactive TUI Dashboard

Warlock includes a full interactive terminal dashboard built with [Textual](https://textual.textualize.io/). It launches by default when you type `warlock` in a terminal.

## Quick Start

```bash
warlock                    # launches TUI
warlock --no-tui ...       # traditional CLI mode
WARLOCK_NO_TUI=1 warlock   # force CLI mode via env var
```

Non-TTY environments (pipes, CI scripts) automatically fall back to the traditional CLI.

## Theme: Arcane Elegance

Purple-accented dark theme (`#a78bfa` on `#08081a`), keyboard-first navigation, with severity-colored status badges (red/amber/yellow/green).

## Screens

| # | Screen | Description | Hotkey |
|---|--------|-------------|--------|
| 1 | Remediations | Home dashboard — remediation queue sorted by overdue/severity | `1` |
| 2 | Findings | Severity-prioritized finding explorer | `2` |
| 3 | Controls | Control results by framework | `3` |
| 4 | POA&M | Plan of Action & Milestones tracker | `4` |
| 5 | Pipeline | Pipeline run history and connector health | `5` |
| 6 | Frameworks | Compliance posture across all 14 frameworks | `6` |
| 7 | Vendors | Vendor risk scores and assessment status | `7` |

## Navigation

- **Left sidebar** — persistent icon nav, click or press `1`-`7`
- **`j`/`k`** — move selection up/down in any list
- **`Enter`** — expand detail view (shows impacted systems, CLI commands, control impact)
- **`Esc`** — collapse detail / go back
- **`Ctrl+K`** — command palette (fuzzy search across entities and all 120+ CLI commands)
- **`t`** — transition remediation status
- **`a`** — assign remediation
- **`r`** — refresh current screen data
- **`q`** — quit

## Remediation Drill-In

The home screen's detail pane expands to show:

1. **Impacted Systems** — system profiles affected, with ATO status
2. **Remediation Commands** — copy-pasteable CLI commands (AWS CLI, Terraform, etc.) with step-by-step progress
3. **Control Impact** — which controls across which frameworks are non-compliant
4. **Activity Timeline** — status changes, assignments, evidence uploads

Commands are sourced from remediation steps, connector-type templates, and Terraform module lookups.

## Architecture

- **Framework:** Textual 8.x (by the Rich team)
- **Data access:** Hybrid — direct SQLAlchemy for reads (zero latency), optional API client for heavy operations
- **Package:** `warlock/tui/` — app, screens, widgets, data layer
- **Theme:** `warlock/tui/theme.tcss` — Textual CSS with design tokens
