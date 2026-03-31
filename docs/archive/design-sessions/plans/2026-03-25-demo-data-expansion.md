# Demo Data Expansion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every CLI command, dashboard, and report show rich, realistic data after `make demo` — including time-series depth, volume, and scenario coverage.

**Architecture:** All changes go into `scripts/demo_seed.py` (new seed functions appended at end, called from the main seed flow). `warlock collect` gets a `--demo` flag to re-run mock connectors. No changes to core pipeline, models, or API code.

**Tech Stack:** Python, SQLAlchemy, Click, existing warlock models/pipeline

**IMPORTANT — demo_seed.py rules:**
- This is the #1 conflict-prone file (21K lines). ONE agent at a time.
- After ANY change, run: `make reset` and verify ALL previously seeded data still works, not just the current task's data. If any previous command regresses, fix before proceeding.
- All datetimes must use `ensure_aware()` or `datetime.now(timezone.utc)`.
- All IDs use `str(uuid.uuid4())`.
- Use `session.add_all([...])` for bulk inserts, `session.flush()` between phases that need FK refs.
- **Seed time budget:** If seed takes >3 minutes after any change, STOP and report before continuing.
- **Hash chain safety:** Never update fields that are part of SHA-256 hash computation after pipeline runs. Check `sha256` property of `RawEventData`/`FindingData` to see which fields are hashed. If backdating timestamps, do it BEFORE the pipeline, not after.
- **Rollback plan:** If any phase makes the seed >3 minutes or breaks QA, `git revert` that phase's commits before continuing.
- **Every task Step 1:** ALWAYS grep the target CLI command to understand its actual data source before designing seed data. Do NOT assume AuditEntry-based queries — many commands query real tables directly.

---

## Phase 1: Fix `warlock collect` post-seed

### Task 1.1: Add `--demo` flag to `warlock collect`

**Files:**
- Modify: `warlock/cli/pipeline.py:21-61`

- [ ] **Step 1: Read the existing `collect` command and `build_pipeline` loader**

Read `warlock/cli/pipeline.py` and `warlock/pipeline/loader.py` to understand how the production pipeline discovers connectors.

- [ ] **Step 2: Add `--demo` flag to collect command**

Add a `--demo` boolean flag. When set, run `subprocess.run([sys.executable, "scripts/demo_seed.py"], check=True)` to re-execute the demo seed as a subprocess (do NOT try to import from demo_seed.py — it has module-level side effects and is 21K lines). When no connectors are configured AND `--demo` is not set, print a helpful message:

```
No connectors configured. Run 'warlock collect --demo' to re-run with demo mock connectors,
or configure real connectors in .env (see .env.example).

Demo data was loaded by 'make demo'. Use 'warlock findings', 'warlock results', etc. to explore it.
```

- [ ] **Step 3: Test manually**

```bash
make reset
warlock collect          # should show helpful message, not zeros
warlock collect --demo   # should run mock connectors and show real numbers
```

- [ ] **Step 4: Commit**

```bash
git add warlock/cli/pipeline.py
git commit -m "feat: add --demo flag to warlock collect, show guidance when no connectors configured"
```

---

## Phase 2: Fill zero-data gaps

### Task 2.1: Ensure KRIs show meaningful values

**Files:**
- Modify: `scripts/demo_seed.py` (ensure underlying data produces non-trivial KRI values)

- [ ] **Step 1: Grep `warlock/cli/dashboard_cmd.py` for `_KRI_REGISTRY` to understand how KRIs work**

KRIs are NOT AuditEntry rows. They are live queries in a hardcoded `_KRI_REGISTRY` dict that runs SQL against real tables (Finding, ConnectorRun, ControlResult, POAM, RawEvent). The seed must ensure the underlying data produces interesting KRI values.

- [ ] **Step 2: Check which KRIs exist and what data they need**

Read `_KRI_REGISTRY` in `dashboard_cmd.py`. For each KRI, verify the seed creates enough data to produce non-zero, non-trivial values. If any KRI shows 0 or 100% (boring), add targeted seed data to make it realistic. Key targets:
- Overdue POA&M count should be >= 2 (seed overdue POA&Ms in Task 5.1)
- Critical finding rate should be non-zero (existing findings have severities)
- Connector error rate should show some failures (add 1-2 failed ConnectorRuns)

- [ ] **Step 3: Also check `warlock reports kri` — grep `reports_cmd.py` for how it queries KRI data**

If `reports kri` uses a different data source than `dashboard kri`, ensure both are covered.

- [ ] **Step 4: Test**

```bash
make reset
warlock dashboard kri list    # should show KRIs with meaningful non-zero values
warlock reports kri           # should show KRI report
```

- [ ] **Step 5: Commit**

### Task 2.2: Seed BCP data (DR schedules, BIA records)

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Grep `warlock/cli/bcp_cmd.py` for expected AuditEntry action strings**

Find what actions `bcp dr-test schedule` and `bcp bia` query for.

- [ ] **Step 2: Add `_seed_bcp_data(session)` function**

Seed:
- 4 DR test schedules (quarterly cadence for 4 systems)
- 4 BIA records (impact assessments for each system profile)
- 2 DR test results with detailed outcomes (supplement existing 3)

- [ ] **Step 3: Test**

```bash
make reset
warlock bcp dr-test schedule  # should show schedule table
warlock bcp bia               # should show BIA results
```

- [ ] **Step 4: Commit**

### Task 2.3: Seed training campaigns

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Grep `warlock/cli/training_cmd.py` for expected AuditEntry action strings**

- [ ] **Step 2: Add `_seed_training_campaigns(session)` function**

Seed 4 training campaigns:
- Annual Security Awareness 2026 (completed, 98% pass rate)
- Phishing Simulation Q1 (completed, 12% click rate)
- HIPAA Privacy Training (in_progress, 76% complete)
- Incident Response Tabletop (scheduled, 0% complete)

- [ ] **Step 3: Test and commit**

### Task 2.4: Seed ConMon deviations and significant changes

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Grep `warlock/cli/conmon_cmd.py` for expected query patterns**

- [ ] **Step 2: Add `_seed_conmon_data(session)` function**

Seed:
- 5 ConMon deviations (controls assessed outside their monitoring frequency window)
- 3 significant change records (infrastructure changes triggering re-assessment)

- [ ] **Step 3: Test and commit**

### Task 2.5: Seed richer ROPA data

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Check what `privacy ropa` queries**

- [ ] **Step 2: Enhance ROPA seed data**

Add 5 processing activities with full ROPA fields: purpose, lawful basis, data categories, recipients, retention periods, transfer mechanisms.

- [ ] **Step 3: Test and commit**

---

## Phase 3: Time depth — 90 days of history

### Task 3.1: Expand PostureSnapshots from 30 to 90 days

**Files:**
- Modify: `scripts/demo_seed.py` — `seed_phase4_posture_snapshots()` function

- [ ] **Step 1: Verify `warlock posture-history` accepts a days flag**

```bash
warlock posture-history --help   # check for -d / --days flag name
```

- [ ] **Step 2: Modify `seed_phase4_posture_snapshots` to cover 90 days**

Change the loop from 30 days to 90 days. Add slight variance to simulate organic posture drift (scores should gradually improve over the 90-day window with occasional dips).

- [ ] **Step 3: Test**

```bash
make reset
warlock posture-history --days 90   # use the actual flag name from Step 1
warlock reports trend               # should show meaningful trend
```

- [ ] **Step 3: Commit**

### Task 3.2: Expand PipelineRun history to 90 days

**Files:**
- Modify: `scripts/demo_seed.py` — `_seed_pipeline_runs()` function

- [ ] **Step 1: Replace 3 pipeline runs with 90 daily runs**

Create 90 PipelineRun records, one per day over the last 90 days. Each should have:
- Realistic `started_at`, `completed_at` (duration 30-120 seconds)
- Incrementing connector/finding/result counts (slight growth over time)
- 2-3 "failed" runs scattered in the history
- Most recent run should match current seed numbers

- [ ] **Step 2: Test and commit**

### Task 3.3: Backdate findings across 90 days

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Check if `observed_at` is part of the SHA-256 hash**

Read `warlock/normalizers/base.py` — check the `FindingData.sha256` property to see which fields are hashed. If `observed_at` is NOT in the hash, it's safe to backdate post-pipeline. If it IS in the hash, the backdating must happen in the mock connectors BEFORE the pipeline runs, by generating findings with past dates.

- [ ] **Step 2: Spread finding `observed_at` timestamps across 90 days**

Using the approach determined in Step 1, spread findings across 90 days.

- ~200 findings backdated to 60-90 days ago (stale)
- ~500 findings backdated to 30-60 days ago
- ~1000 findings backdated to 7-30 days ago
- Remainder stays at "today"

- [ ] **Step 2: Test**

```bash
make reset
warlock findings aging --severity critical  # should show aged findings
warlock reports sla                         # should show SLA breaches
warlock lake-analytics trends findings      # should show trend data (if lake enabled)
```

- [ ] **Step 3: Commit**

### Task 3.4: Expand ComplianceDrift and ChangeEvent history

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Expand drift events from 10 to 30, spread across 90 days**

- [ ] **Step 2: Expand change events from 40 to 100, spread across 90 days**

Include a mix of:
- Infrastructure changes (CloudTrail — IAM role changes, security group mods)
- Code changes (GitHub — PR merges affecting security-relevant code)
- Config changes (ServiceNow — firewall rule changes, DNS modifications)
- Vendor changes (new vendor onboarded, vendor contract renewed)

- [ ] **Step 3: Test and commit**

---

## Phase 4: Volume increase

### Task 4.1: Increase raw events per connector

**Files:**
- Modify: `scripts/demo_seed.py` — mock connector classes

- [ ] **Step 1: Identify the top 20 connectors by real-world event volume**

AWS, Azure, GCP, CrowdStrike, Okta, Entra ID, Tenable, Qualys, Snyk, Splunk should each produce 20-50 raw events (not 3-5). Cloud providers should generate events for each service (IAM, S3, EC2, VPC, CloudTrail, GuardDuty, etc.).

- [ ] **Step 2: Increase mock event generation for top connectors**

Target: ~3,000 raw events total (up from 589). This should cascade to ~25,000-30,000 findings and ~1.5-2M control mappings.

**CAUTION:** This will significantly increase seed time. After changes, time the seed: `time make reset`. If >3 minutes, STOP and report. Consider reducing volume targets or adding batch optimizations before proceeding.

- [ ] **Step 3: Time the seed and check viability**

```bash
time make reset   # must complete in < 3 minutes
```

If too slow, reduce target from 3,000 to 1,500 raw events and re-test.

- [ ] **Step 4: Do NOT update docs yet — wait for Phase 6**

All doc updates happen in Task 6.1 after final numbers are known. Do not update docs mid-flight.

- [ ] **Step 5: Commit**

### Task 4.2: More incidents with severity classification

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Create 10 properly classified incidents**

Use the Issue model with fields set as the incident workflow expects:
- 3 critical (data breach, ransomware, unauthorized access)
- 3 high (privilege escalation, exposed credentials, compliance violation)
- 2 medium (suspicious login, policy exception)
- 2 low (phishing attempt blocked, failed scan)

Each should have: severity, classification, `finding_id` linking to a real finding, timeline entries via AuditEntry/IssueComment.

- [ ] **Step 2: Test**

```bash
make reset
warlock incidents list                     # should show 10+ incidents
warlock incidents list --severity critical # should show 3
warlock correlate finding-to-incident      # should trace incident to finding
```

- [ ] **Step 3: Commit**

---

## Phase 5: Scenario richness

### Task 5.1: Richer POA&M lifecycle scenarios

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Add 10 more POA&Ms with realistic lifecycle data**

- 2 overdue (past `scheduled_completion`, still `in_progress`) — these should trigger calendar/alerts
- 2 with milestones approaching within 7 days
- 2 with cost estimates and vendor dependencies
- 2 recently completed with verification evidence
- 2 with risk acceptance (one pending AO approval, one approved with expiry in 30 days)

- [ ] **Step 2: Test and commit**

### Task 5.2: Active DSARs and privacy scenarios

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Seed active DSAR lifecycle**

- 2 new DSARs (submitted, awaiting verification)
- 1 in_progress DSAR (data collection underway, 15 of 30 days elapsed)
- 1 completed DSAR (exported, delivered)
- 1 overdue DSAR (past 30-day deadline — should trigger alerts)
- 2 data breach notifications (1 reported to authority, 1 pending)

- [ ] **Step 2: Test and commit**

### Task 5.3: Vendor assessments and renewals

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Enhance vendor data**

- 5 vendors with assessment due dates in next 30 days
- 3 vendors with SOC 2 reports approaching expiry
- 2 vendors flagged high-risk (SecurityScorecard < 60)
- 1 vendor in offboarding process
- Sub-processor chains for key vendors (Stripe → AWS, Datadog → AWS/GCP)

- [ ] **Step 2: Test and commit**

### Task 5.4: Attestations, training gaps, and calendar items

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Seed expiring attestations and calendar items**

- 3 attestations expiring within 30 days (should appear in `warlock calendar next`)
- 2 personnel with overdue training (should appear in `warlock training overdue`)
- 5 more calendar items: evidence collection deadlines, audit prep meetings, vendor review dates
- 2 risk analyses with cached Monte Carlo results

- [ ] **Step 2: Test and commit**

### Task 5.5: Richer alert and remediation data

**Files:**
- Modify: `scripts/demo_seed.py`

- [ ] **Step 1: Expand alerts and remediations**

- 10 more alerts across all severity levels, some acknowledged, some with escalation
- 5 more remediation records with step-by-step plans and completion percentages
- Link remediations to specific POA&Ms and findings

- [ ] **Step 2: Test and commit**

---

## Final Verification

### Task 6.1: Full demo smoke test

- [ ] **Step 1: Run `make reset` and verify new expected numbers**
- [ ] **Step 2: Run EVERY command group against the demo and verify non-empty output**

Test at minimum (every major command group):
```bash
# Pipeline
warlock collect          # should show helpful message (no connectors)
warlock collect --demo   # should run mock connectors
warlock pipeline status

# Core compliance
warlock briefing
warlock coverage
warlock findings
warlock results --status non_compliant
warlock control AC-2

# Incidents & issues
warlock incidents list
warlock incidents list --severity critical
warlock issues

# Governance
warlock poams
warlock poams --overdue
warlock compensating-controls
warlock risk-acceptances
warlock assertions

# Audit & evidence
warlock attestations list
warlock audit-trail
warlock evidence freshness

# Risk
warlock risk
warlock risk-engine

# Vendors
warlock vendors
warlock vendor-mgmt list

# Privacy
warlock privacy dsar list
warlock privacy breach list
warlock privacy ropa
warlock privacy data-map

# BCP & training
warlock bcp bia
warlock bcp dr-test schedule
warlock training status
warlock training campaigns

# Monitoring & trends
warlock drift
warlock conmon status
warlock conmon deviation
warlock posture-history
warlock cadence
warlock effectiveness

# Dashboard & reports
warlock dashboard kri list
warlock reports executive
warlock reports trend
warlock reports kri
warlock reports sla

# Calendar & correlation
warlock calendar next
warlock correlate trace <finding_id>

# Lake & analytics
warlock lake-analytics summary

# Systems & users
warlock systems
warlock users
warlock personnel
```

Also run: `grep -rn "589\|5,47\|5,48\|373,852" --include="*.md" --include="*.yaml" --include="*.yml" --include="*.sh"` to find every doc that needs its numbers updated.

Every command must show non-empty, non-zero results. Any empty result is a FAILURE (Rule 8).

- [ ] **Step 3: Update all docs with new expected numbers**

Run `make verify-docs` and fix every doc. Update CLAUDE.md Rule 4 expected output.

- [ ] **Step 4: Run full QA gate**

```bash
./scripts/qa.sh
```

- [ ] **Step 5: Commit and prepare for push**
