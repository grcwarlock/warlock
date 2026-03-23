# Warlock Issue Log — Consolidated

**Last updated:** 2026-03-23
**Sources:** 2026-03-22 stress test + 2026-03-23 comprehensive CLI test (170 commands)

---

## Status Summary

| Category | Total | Fixed | Open |
|----------|-------|-------|------|
| Bugs (crashes) | 19 | 11 | 8 |
| API issues | 3 | 2 | 1 |
| Missing features / gaps | 13 | 13 | 0 |
| UX issues | 4 | 4 | 0 |
| Missing commands | 2 | 0 | 2 |
| CLI inconsistencies | 5 | 0 | 5 |
| Cross-flow gaps | 9 | 0 | 9 |

---

## RESOLVED — 2026-03-22 Stress Test Issues (ALL FIXED)

Fixed in commits `b4387ed`, `2beade8`, `a76fda3`.

<details>
<summary>Click to expand resolved items</summary>

### Bugs
- [x] **BUG-1** `lake-analytics summary` — datetime naive/aware TypeError
- [x] **BUG-2** `lake-analytics freshness` — same datetime TypeError
- [x] **BUG-3** `lake-analytics sources` — same datetime TypeError
- [x] **BUG-4** `lake-analytics anomaly detect` — fromisoformat on non-string
- [x] **BUG-5** `lake-analytics trends findings` — same fromisoformat error
- [x] **BUG-6** `reports sla` — datetime naive/aware TypeError
- [x] **BUG-7** `incidents list` — Rich MarkupError from unescaped brackets

### API
- [x] **API-1** Root `/health` + `/healthz` endpoints added
- [x] **API-2** `/readyz` endpoint added

### Gaps
- [x] **GAP-1** `warlock systems --status non_compliant` added
- [x] **GAP-2** Demo seed populates 28 hash-chained audit trail entries
- [x] **GAP-3** `results --system` filter added
- [x] **GAP-4** Personnel records enriched with real statuses, MFA, training
- [x] **GAP-5** Demo seed creates 4 attestations
- [x] **GAP-6** Demo seed creates change requests
- [x] **GAP-7** `lake init` shows backfill hint
- [x] **GAP-8** Policy exceptions show policy/approver metadata
- [x] **GAP-9** Findings backdated 7-90 days for SLA/aging demos
- [x] **GAP-10** Some findings are aged past SLA for demo purposes
- [x] **GAP-11** Data silos enriched with encryption, logging, classification
- [x] **GAP-12** Vendors have varied risk scores (30-89)
- [x] **GAP-13** Personnel training enrollment populated

### UX
- [x] **UX-1** CLI groups show default list instead of erroring
- [x] **UX-2** `results --limit` rejects 0 via IntRange(min=1)
- [x] **UX-3** Coverage rate excludes `not_assessed` from denominator
- [x] **UX-4** KRI dashboard expanded from 4 to 8 indicators

### API (partial)
- [x] **API-3** Login email/username handling addressed

</details>

---

## OPEN — 2026-03-23 CLI Test Bugs

### CRITICAL (blocks core workflows)

- [ ] **CLI-BUG-009**: `incidents update --status investigating` — IntegrityError: CHECK constraint failed. CLI offers `investigating/contained/resolved` but DB requires `assigned/in_progress/remediated/verified/closed/risk_accepted`. **Entire incident lifecycle is blocked.** (`incidents_cmd.py:39`)

### HIGH (crashes or wrong data)

- [ ] **CLI-BUG-004**: `vendor-mgmt reassess-due` — datetime naive/aware TypeError. Missing `ensure_aware()` on `v.last_assessment`. (`vendors_cmd.py:389`)
- [ ] **CLI-BUG-005**: `vendor-mgmt contracts` — datetime naive/aware TypeError. Missing `ensure_aware()` on `v.contract_expires`. (`vendors_cmd.py:453`)
- [ ] **CLI-BUG-007**: `poam list --format json` — invalid JSON output. Raw `\n` in string values not escaped. Needs `json.dumps()` instead of manual string construction.
- [ ] **CLI-BUG-008**: `control-hub --format json` — AttributeError: `Attestation` has no `owner` field. Should use `prepared_by` or `submitted_by`. (`control_cmd.py:79,125`)
- [ ] **CLI-BUG-010**: `calendar export --format ics` — ImportError: `PersonnelRecord` doesn't exist. Model is named `Personnel`. (`calendar_cmd.py:251`)
- [ ] **CLI-BUG-011**: `link training-access` — ImportError: `TrainingRecord` doesn't exist. (`interop_cmd.py:538`)

### MEDIUM

- [ ] **CLI-BUG-012**: `bulk import-findings --dry-run` crashes on empty file. Should validate file before parsing.

---

## OPEN — Missing Commands

- [ ] **MC-001**: `correlate top-risk` — referenced but doesn't exist. Should show top risk concentrations.
- [ ] **MC-002**: `comply gap-analysis` — doesn't exist. Users find `correlate gap-analysis` instead. Add alias or document.

---

## OPEN — CLI Inconsistencies

- [ ] **CI-001 MEDIUM**: Framework argument inconsistency — some commands accept positional (`soc2`), some require `-f soc2`, some accept both. Standardize all to accept both.
- [ ] **CI-002 LOW**: Vendor tier naming — CLI accepts `1/2/3/critical`, display shows `high/medium/low/critical`. No clear mapping.
- [ ] **CI-003 LOW**: `incidents create` uses `--severity` but displays "Priority" column. No `--control` or `--framework` flags.
- [ ] **CI-004 LOW**: `incidents update` status choices don't match DB (duplicate of CLI-BUG-009).
- [ ] **CI-005 LOW**: `frameworks list` shows 15 frameworks including `soc2_points_of_focus` with 0 families/0 controls. CLAUDE.md documents 14 frameworks. Hide or remove ghost framework.

---

## OPEN — Cross-Flow Gaps (missing linkages between domains)

### HIGH — Core GRC workflows

- [ ] **XF-001 CRITICAL**: No `findings create-issue` command. The most basic GRC workflow (find problem → create ticket) requires manual ID copying.
- [ ] **XF-004 HIGH**: `poam create` has no `--finding-id` flag. Can't tie POA&M to source finding.
- [ ] **XF-005 HIGH**: `bulk link-findings-to-issues` advertised in `bulk stats` output but doesn't exist.
- [ ] **XF-002 HIGH**: `privacy breach create` has no `--incident-id` flag. Can't link breach to incident.
- [ ] **XF-003 HIGH**: `privacy dsar create` has no `--breach-id` flag. Can't link DSAR to breach.

### MEDIUM — Workflow automation

- [ ] **XF-006**: Closing a POA&M doesn't update control compliance status or suggest re-assessment.
- [ ] **XF-007**: Creating/closing incidents doesn't trigger control re-assessment.
- [ ] **XF-008**: `control-hub` doesn't show linked incidents (only POA&Ms and attestations).
- [ ] **XF-009**: Privacy breach response has no automation cascade (incident → breach → DSAR requires 3 manual commands).

---

## Workflow Chain Status (7 tested)

| Workflow | Status | Blocking Issues |
|----------|--------|-----------------|
| 1. Finding → Triage → Issue → POA&M → Closure | **BROKEN** | CLI-BUG-008, CLI-BUG-009 |
| 2. Compliance Assessment → Gap Analysis → Evidence | **PASS** | — |
| 3. Vendor Management Flow | **BROKEN** | CLI-BUG-004, CLI-BUG-005 |
| 4. Privacy Breach Cascade | **PASS (no linking)** | XF-002, XF-003 |
| 5. Bulk Operations | **MOSTLY PASS** | CLI-BUG-012 |
| 6. OSCAL Export Package | **PASS** | CI-001 (minor) |
| 7. JSON Pipeline | **BROKEN** | CLI-BUG-007, CLI-BUG-008 |

---

## Fix Priority Order

**Phase A — Unblock core workflows (~2 hours):**
1. CLI-BUG-009: Fix incident status enum mismatch (10 min)
2. CLI-BUG-004/005: `ensure_aware()` in vendors_cmd.py (15 min)
3. CLI-BUG-008: Fix `Attestation.owner` → correct field name (10 min)
4. CLI-BUG-010/011: Fix model import names (15 min)
5. CLI-BUG-007: Fix POA&M JSON serialization (15 min)
6. XF-001: Add `findings create-issue` command (30 min)

**Phase B — Polish and linking (~3 hours):**
7. CI-001: Standardize positional/flag framework args across commands
8. XF-004/005: Add `--finding-id` to `poam create`, add `bulk link-findings-to-issues`
9. XF-002/003: Add `--incident-id` to breach create, `--breach-id` to DSAR create
10. MC-001/002: Add missing commands or aliases
11. CI-005: Hide `soc2_points_of_focus` from framework list or fix it

**Phase C — Workflow automation (post-v1.0):**
12. XF-006/007: Auto re-assessment on POA&M/incident closure
13. XF-008: Show incidents in control-hub
14. XF-009: Privacy breach cascade automation
