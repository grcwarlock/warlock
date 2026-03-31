# Control Browser — Design Spec

**Date:** 2026-03-20
**Status:** Approved

## Problem

Remediation data exists (1,779 KB entries with steps, console paths, CLI commands) but the only way to access it is via `warlock remediate <issue-id>`, which requires knowing an Issue or POA&M ID. There's no way to browse by control ID, see which resources pass/fail, and get remediation commands.

## Solution

### 1. `warlock control <control_id>` CLI command

Shows control status across all resources with remediation guidance.

**Arguments:**
- `control_id` (required) — e.g., SC-28, AC-2, CC6.1
- `--framework / -f` — explicit framework (auto-detected if only one matches)
- `--remediate / --no-remediate` — show/hide remediation (default: show)
- `--ai / --no-ai` — AI-enhanced per-resource remediation commands
- `--ask` — interactive AI reasoning about this control

**Output:**
- Control name and description (from framework YAML)
- Compliance status (compliant/non_compliant/partial counts)
- Passing resources table (resource_id, resource_type, source/provider)
- Failing resources table (same columns, red-highlighted)
- KB remediation (summary, steps, console_path, recommended_reading)
- AI remediation per failing resource (specific CLI commands) — only when `--ai`

**Data flow:**
1. Query `ControlResult` rows matching control_id (and framework if specified)
2. For each result, join with `Finding` via `finding_id` to get resource details
3. Group into passing (status=compliant) and failing (status!=compliant)
4. Load KB remediation via `get_remediation(framework, control_id)`
5. If `--ai`, call `AIService.reason(REMEDIATION_GUIDANCE)` with context containing failing resource IDs, types, providers, and KB entry

### 2. `get_control_detail()` in remediation_loader.py

New function that assembles the full control view:

```python
def get_control_detail(session, control_id, framework=None):
    """Get full control detail: status, resources, remediation."""
    return {
        "control_id": control_id,
        "framework": framework,
        "description": "...",  # from framework YAML
        "total_resources": N,
        "compliant_count": N,
        "non_compliant_count": N,
        "passing_resources": [...],
        "failing_resources": [...],
        "remediation": {
            "summary": "...",
            "steps": [...],
            "console_path": "...",
            "recommended_reading": [...],
        },
    }
```

### 3. API endpoint: `GET /api/v1/controls/{control_id}`

Returns the full control detail JSON. Query params: `framework` (optional).

Response includes: status counts, passing/failing resource lists, full remediation (summary + steps + console_path), and crosswalk mappings to other frameworks.

### 4. TUI Coverage tab click-to-detail

When a control row is clicked in the Coverage screen's DataTable, a detail panel appears below showing:
- Passing/failing resource breakdown
- KB remediation steps
- Console path
- If AI configured, a "Get AI Remediation" button that generates per-resource commands

## Files to create/modify

| File | Change |
|------|--------|
| `warlock/assessors/remediation_loader.py` | Add `get_control_detail(session, control_id, framework)` |
| `warlock/cli.py` | Add `warlock control` command |
| `warlock/api/app.py` | Add `GET /api/v1/controls/{control_id}` endpoint |
| `warlock/tui/screens/coverage.py` | Add click-to-detail panel with remediation |

## Testing

- `warlock control SC-28` shows passing/failing resources from demo data
- `warlock control AC-2 --framework nist_800_53` filters to NIST
- `warlock control SC-28 --ai` generates per-resource CLI commands (when AI configured)
- API endpoint returns full JSON
- TUI click-to-detail renders remediation panel
- QA gate passes (22+ checks)
