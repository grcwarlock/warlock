# Demo → Product: What Needs to Be Built

> This document lists functionality shown in the static demo that needs to be built, fixed, or wired up in the actual Warlock product to make the demo a reality. Separate from the main project TODO.

---

## Status Legend
- **MISSING** — Feature does not exist in the codebase at all
- **STUBBED** — Code structure exists but not functional
- **NAME MISMATCH** — Feature exists but demo uses wrong command name
- **NEEDS WIRING** — Backend exists, needs CLI/API/frontend integration
- **NEEDS FRONTEND** — Backend works via CLI, but no web UI exists

---

## 1. Features Completely Missing (Must Build)

### 1a. Alerts System
**Demo shows**: Security alerts view with 200 alerts, severity/status filters, MITRE ATT&CK techniques, detail panels
**Reality**: No `Alert` model in `models.py`. No alert rules engine. No alert subscription system. Connector data flows through Findings, not Alerts.
**To build**:
- [ ] `Alert` SQLAlchemy model (alert_id, title, severity, source, status, technique, tactic, affected_host, detected_at, resolved_at)
- [ ] Alembic migration for alerts table
- [ ] Alert rules engine (map Finding patterns → Alert triggers)
- [ ] `warlock alerts` CLI command with filters (--severity, --status, --source)
- [ ] Alert detail in CLI output
- [ ] API routes: GET /alerts, GET /alerts/{id}, PATCH /alerts/{id}
- [ ] MITRE ATT&CK technique mapping (technique ID + tactic)
- [ ] Alert → Finding linkage (which findings triggered the alert)

### 1b. Unified Cloud Inventory
**Demo shows**: Cloud Environments view with 600 instances across AWS/Azure/GCP, region/state filters, tags, security groups
**Reality**: Cloud connectors (AWS, Azure, GCP, Wiz, etc.) collect raw events, but there's no unified "cloud inventory" model or command.
**To build**:
- [ ] `CloudResource` model (or enrich existing RawEvent with structured cloud metadata)
- [ ] `warlock cloud` CLI command (list instances, filter by provider/region/state)
- [ ] Cloud resource detail (instance ID, type, state, IPs, VPC, security groups, tags)
- [ ] Aggregation: instances per cloud, running vs stopped vs terminated
- [ ] API route: GET /cloud/resources with provider/region/state query params

### 1c. Device Management
**Demo shows**: Devices view with 400 devices, platform/compliance filters, encryption/firewall status, user linkage
**Reality**: Endpoint connectors (CrowdStrike, Intune, Jamf, SentinelOne, Sophos) exist but no unified Device model.
**To build**:
- [ ] `Device` model (device_id, name, serial, platform, os_version, encrypted, firewall, screen_lock, compliant, last_seen, user_email, model)
- [ ] Alembic migration
- [ ] `warlock devices` CLI command with platform/compliance filters
- [ ] Device ↔ User linkage
- [ ] Device compliance scoring (encrypted + firewall + screen_lock + agent_online = compliant)
- [ ] API route: GET /devices with filters

### 1d. Storage Analysis
**Demo shows**: Storage & Buckets view with 80 buckets, public access warnings, encryption/versioning/logging status
**Reality**: Cloud connectors collect storage data but no unified storage view.
**To build**:
- [ ] `StorageBucket` model (or derive from existing connector data)
- [ ] `warlock storage` CLI command (list buckets, filter by cloud/public/encryption)
- [ ] Public access detection and warnings
- [ ] Misconfiguration scoring
- [ ] API route: GET /storage/buckets

---

## 2. CLI Command Name Mismatches (Fix Demo or Fix CLI)

These features WORK but the demo uses different names than the actual CLI.

| Demo Command | Actual CLI Command | Fix |
|---|---|---|
| `warlock drift` | `warlock drift` (exists but is `drift_list` internally) | OK — CLI name matches |
| `warlock cadence` | `warlock cadence` (exists as `cadence_check`) | OK — CLI name matches |
| `warlock effectiveness` | `warlock effectiveness` (exists as `effectiveness_report`) | OK — CLI name matches |
| `warlock sufficiency` | `warlock sufficiency` (exists as `sufficiency_check`) | OK — CLI name matches |
| `warlock systems` | `warlock systems` (exists) | OK |
| `warlock data-silos` | `warlock data-silos` (exists) | OK |
| `warlock remediation` (view name) | `warlock remediate <id>` (command) | Demo view name vs CLI command — different thing, OK |

**Verdict**: No actual name mismatches in the CLI commands. The demo accurately represents the command names.

---

## 3. Features That Exist But Need a Web Frontend

The demo implies a web dashboard. In reality, ALL of these are CLI/API only. If we want a real web app:

### 3a. Full Web Application (The Big One)
- [ ] Choose stack: Next.js + React (recommended per CLAUDE.md patterns)
- [ ] API client layer (talk to FastAPI backend)
- [ ] Authentication UI (JWT login, OIDC support)
- [ ] Dashboard page (mirrors demo dashboard)
- [ ] Every view from the demo as a real React page
- [ ] Real-time updates (WebSocket or polling for pipeline status)
- [ ] Role-based access (ABAC already exists in API, need UI enforcement)

### 3b. OR: Terminal UI (TUI) — Lighter Alternative
- [ ] `warlock tui` command (Textual/Rich based — import already exists in codebase)
- [ ] Dashboard with stats, compliance bars
- [ ] Table views with filtering
- [ ] Detail panels

---

## 4. Backend Exists, Needs Polish/Wiring

### 4a. AI Reasoning in Demo Detail Panels
**Demo shows**: AI analysis with confidence %, bullet reasoning, evidence sources on every failing control
**Reality**: AI service exists (`warlock/ai/`) with full Anthropic/Gemini/OpenAI/Ollama support, but:
- [ ] AI reasoning output format doesn't match demo format (needs structured JSON with confidence, reasoning[], evidence[], recommendation)
- [ ] `--ai` flag on `warlock control <id>` returns prose, not structured analysis
- [ ] Need AI output adapter that produces: `{confidence: 0.92, reasoning: [...], evidence: [...], recommendation: "..."}`
- [ ] API route for AI assessment: POST /ai/assess with control_id + framework

### 4b. Remediation Workflow UI State Machine
**Demo shows**: Interactive 5-stage workflow (Broken → Investigate → Remediate → Verify → Closed)
**Reality**: Issue workflow exists (open → assigned → in_progress → resolved → closed) but:
- [ ] Map demo stages to actual workflow states
- [ ] "Investigate" action should trigger AI analysis automatically
- [ ] "Begin Remediation" should generate and display CLI commands
- [ ] "Mark Remediated" should transition issue + trigger re-assessment
- [ ] Verification step should run `warlock control <id> --framework <fw>` and show result
- [ ] Need API endpoint: POST /remediate/{issue_id}/workflow-step

### 4c. Pipeline Visualization Real-Time
**Demo shows**: Pipeline flow (82→358→5008→373852→14) with clickable stages
**Reality**: Pipeline orchestrator exists and these numbers are real (from demo seed), but:
- [ ] Need real-time pipeline status API: GET /pipeline/status
- [ ] Need per-connector collection status: GET /pipeline/connectors/{id}/status
- [ ] WebSocket for live pipeline progress during collection
- [ ] Hash chain verification endpoint: GET /pipeline/verify-chain

### 4d. Audit Simulation Enhancements
**Demo shows**: Framework selector, date picker, projected coverage, AI readiness assessment
**Reality**: `warlock simulate-audit` exists and works, but:
- [ ] Need date picker input for "simulate as of date X"
- [ ] AI readiness narrative needs structured output (not just prose)
- [ ] Need projected vs actual comparison view
- [ ] API route: GET /audit/simulate?framework=X&date=Y

### 4e. Cross-View Navigation / Deep Linking
**Demo shows**: Click a vuln's affected_resource → navigate to Cloud view filtered to that resource
**Reality**: CLI has no concept of cross-navigation. For a web frontend:
- [ ] URL-based routing with query params: `/cloud?filter=instance-id-xyz`
- [ ] Deep link generation from any entity to related entities
- [ ] Breadcrumb trail showing navigation path

---

## 5. Data Generation for Demo/Testing

### 5a. Demo Seed Completeness
**Current**: `demo_seed.py` produces 81 connectors, 5008 findings, 373K control results
**Missing from seed**:
- [ ] Alert records (need Alert model first — see 1a)
- [ ] Cloud resource inventory records (need model — see 1b)
- [ ] Device records (need model — see 1c)
- [ ] Storage bucket records (need model — see 1d)
- [ ] Drift events (model exists: `ComplianceDrift`, but demo seed doesn't generate them)
- [ ] Posture snapshots over time (model exists: `PostureSnapshot`, seed creates point-in-time only)

### 5b. Demo Data Realism
- [ ] Drift events should show realistic degradation/improvement patterns over 90 days
- [ ] Posture snapshots should show trend lines (daily snapshots for 90 days)
- [ ] Issues should have realistic timelines (created → assigned → in_progress with comments)
- [ ] POA&Ms should have milestone progress tracking

---

## 6. Export / Reporting Gaps

### 6a. Demo-Quality PDF Report
**Demo implies**: Executive-quality compliance reports
**Reality**: OSCAL JSON export works, but:
- [ ] PDF report generation (use ReportLab or WeasyPrint)
- [ ] Executive summary template
- [ ] Framework-specific compliance report
- [ ] Risk analysis report with charts
- [ ] Audit readiness report

### 6b. Dashboard Embedding
- [ ] Embeddable compliance widget (iframe-safe HTML)
- [ ] Badge/shield generation (SVG compliance badges for README)
- [ ] Slack/Teams notification integration for drift/alerts

---

## 7. Priority Order for Building

### P0 — Critical for Demo-to-Product (makes the demo real)
1. Alert model + CLI + API (most visible gap)
2. Device model + CLI + API (visible in every endpoint connector)
3. AI reasoning structured output (powers the whole remediation UX)
4. Remediation workflow API (the crown jewel feature)

### P1 — High Value
5. Cloud inventory unified view
6. Storage analysis
7. Pipeline real-time status API
8. Drift event generation in demo seed
9. Posture history time-series in demo seed

### P2 — Web Frontend (Big Effort)
10. Next.js web application (or TUI alternative)
11. Authentication UI
12. Real-time pipeline dashboard
13. Cross-view deep linking

### P3 — Polish
14. PDF report generation
15. Embeddable widgets
16. Notification integrations
17. Demo seed enhancements (drift history, posture trends)

---

## 8. What's Already Done (No Work Needed)

These demo features are **fully backed by real code**:

- Compliance frameworks (14, all working)
- Control results + mapping + assessment
- 82 connectors + 82 normalizers
- Pipeline orchestrator (collect → normalize → map → assess)
- Issues, POA&Ms, Risk Acceptances, Compensating Controls
- FAIR Monte Carlo risk analysis
- Drift detection
- Posture history + sufficiency scoring
- Cadence monitoring
- Effectiveness reporting
- Audit simulation
- Data silos + discovery
- Questionnaire management
- Personnel management
- Systems + control inheritance + dependencies
- OSCAL export (AR, SSP, POA&M)
- Framework diff
- OPA/Rego policy evaluation (670 policies)
- AI service (Anthropic, Gemini, OpenAI, Ollama)
- Hash-chained audit trail
- ABAC + OPA API enforcement
- 42+ CLI commands
- 135+ REST API endpoints
- 556 pytest tests
- Data lake (24 modules, DuckDB, Parquet)
