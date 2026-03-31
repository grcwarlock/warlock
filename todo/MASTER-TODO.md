# Warlock — Master TODO

> **Last updated**: 2026-03-30  
> **Canonical backlog**: Single source of truth for remaining product and engineering work.  
> **Superseded** (moved to `todo/archive/`): historical `TODO.md` (GAPS/STUBS/ARCH — all completed), narrative `run1`–`run4` audits, `connectors-todo.md`.

---

## Engineering hotfix queue (verify first)

Issues confirmed in code; they are **not** renumbered into the audit list below.

*No open items.*

- **ENG-001** (resolved 2026-03-30): Lake paths for connector runs returned `list[dict]` while routes expected ORM-style attributes. Fixed by mapping DuckDB rows to `LakeConnectorRunView` in `warlock/db/repository.py` (`_connector_runs_from_lake_dicts`).

---

## Archive index

| Path | Contents |
|------|----------|
| `todo/archive/historical-gaps-stubs-architecture.md` | Original GAPS/STUBS/ARCHITECTURE merge (`TODO.md`) — 147 items, all complete |
| `todo/archive/audit-runs-2026-03-29/` | Full narrative outputs from 4 parallel audits (pipeline, CLI/API, security, market) |
| `todo/archive/connectors-expansion-completed.md` | Connector expansion note (351 connectors) — completed 2026-03-26 |

---

## 4-run audit backlog (2026-03-29)

> **Method**: Four parallel GRC engineering audits against the live demo database  
> **Sources**: Run 1 (Pipeline/Demo), Run 2 (CLI/API/TUI), Run 3 (Security/Compliance/Exports), Run 4 (Market Research)  
> **Scope**: Bugs, missing features, and competitive gaps vs. Drata, Vanta, Anecdotes, Hyperproof, ServiceNow GRC, OneTrust, Archer, AuditBoard, LogicGate, Wiz, Scrut, Sprinto, Secureframe

### How to Read This File

- **P0** — Crash, data corruption, false confidence, or blocks demo/eval
- **P1** — Broken workflow, missing data, or competitive table stakes
- **P2** — Incomplete feature, weak coverage, or market differentiator
- **P3** — Future roadmap, nice-to-have
- **Effort**: S (<1 day), M (1-3 days), L (3-5 days), XL (1+ week)
- **Source**: R1 = Run 1, R2 = Run 2, R3 = Run 3, R4 = Run 4

Items are deduplicated across runs. Where multiple runs flagged the same issue, all sources are cited.

---

## P0 — CRITICAL (Fix Before Any Demo or Eval)

### Bugs

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 1 | `pipeline verify-chain` wrong hash algorithm | Uses string concatenation; actual chain uses JSON `sort_keys=True`. Reports false breakage ("Chain broken at 93 points") when chain is intact. | S | R1 |
| 2 | Lake reconciliation permanently broken after `make reset` | `make reset` deletes DB but not `lake/` dir. Lake accumulates stale data across resets (577% drift). `make reset` must also `rm -rf lake/`. | S | R1 |
| 3 | Lake backfill not idempotent | Running `lake backfill` twice creates duplicate rows. No upsert/dedup logic. Reconciliation permanently broken after re-run. | M | R1 |
| 4 | Demo seed IntegrityError on `external_auditors.email` | UNIQUE constraint fails when seed creates duplicate auditors within one run. | S | R1 |
| 5 | `evidence gaps` crashes — Rich markup error | `evidence_cmd.py:620` — empty style string produces `[]{text}[/]`, crashing Rich. Anti-pattern fix: `f"[{style}]{text}[/{style}]" if style else escape(text)` | S | R3 |
| 6 | `poam list` returns empty but `poams` shows 26 | Two competing commands for the same entity with different query logic. | S | R2 |
| 7 | Duplicate system profiles | `systems` shows 10 rows but only 5 unique systems. Seed creates duplicates. | M | R2 |
| 8 | `reports pdf` crashes — `reportlab` not in dev deps | PDF generation is a demo feature but dependency is missing from `[dev]` extras. | S | R2 |

### Missing (Demo-Blocking)

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 9 | No CSV output format | `--output-format` only supports `table`/`json`. Auditors need CSV for Excel/SIEM handoff. Every list command needs `--format csv`. | M | R2 |
| 10 | No bulk finding import | `ingest` exists for JSON webhook but no `findings import` for CSV/JSON batch import from external scanners. | L | R2 |
| 11 | No role/permission management CLI | `users list/create` exists but no CLI for managing roles, permissions, or RBAC policies. | M | R2 |

---

## P1 — SIGNIFICANT (Blocks Realistic Usage)

### Bugs / Rule 8 Violations (No Data = Failed Demo)

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 12 | 10 lake subcommands return "No data found" | `lake evidence list/freshness`, `lake incidents list/events`, `lake privacy dsars/processing/transfers`, `lake supply-chain sbom/suppliers/concentration` — all empty despite 119 MB lake data. | L | R1 |
| 13 | `ask` and `lake query` return generic response | Return same summary regardless of question. Without AI, should at least do keyword/SQL queries against the lake. | M | R1 |
| 14 | `coverage` and `simulate-audit` make AI calls when AI disabled | HTTP POST to ollama even with `WLK_AI_ENABLED=false`. Must check flag before calling. | S | R1 |
| 15 | `embeddings` returns "No embeddings found" | No seed data. Rule 8 violation. | S | R1, R2 |
| 16 | `watch-subscriptions` returns "No data found" | Model + API exists, no seed data. | S | R2 |
| 17 | `escalation-policies` returns "No data found" | Model + API exists, no seed data. | S | R2 |
| 18 | `integrations list` shows "No integrations configured" | Demo should show at least one configured integration. | S | R2 |
| 19 | `vendors` command mutates DB on read | Creates new vendor risk findings every invocation. Read-only list should not write data. | M | R2 |
| 20 | `cato-dashboard` shows 0 controls for 8/10 systems | System-to-control mapping incomplete. Only 2 of 10 profiles linked to control results. | M | R2 |
| 21 | 18 database tables completely empty in demo | `api_keys`, `assets`, `branding_configs`, `change_requests`, `compliance_obligations`, `dead_letter_queue`, `delegation_grants`, `embeddings`, `escalation_policies`, `ip_allowlist`, `policy_history`, `risk_dependencies`, `sandbox_environments`, `saved_queries`, `trust_access_requests`, `trust_documents`, `watch_subscriptions`, `workpapers` | M | R3 |
| 22 | Demo seed does NOT create users explicitly | Users exist from ad-hoc runs. Fresh `make reset` may not create them, breaking API auth testing. | S | R3 |
| 23 | OSCAL SSP missing required fields | No `security-impact-level`, `status`, `date-authorized`, `responsible-parties` — fails FedRAMP schema validation. | M | R3 |
| 24 | OSCAL SSP `import-profile` uses unresolvable UUID href | `"href": "#967a8853-..."` points nowhere. Should reference actual profile JSON. Breaks SSP-to-catalog traceability. | S | R3 |
| 25 | Audit trail has only 93 entries for 747K+ control results | <0.01% coverage. Pipeline operations not generating audit entries at scale. Assessor would flag immediately. | L | R3 |

### Missing CLI/API/TUI Coverage

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 26 | TUI only has 7 of ~20 needed screens | Missing: incidents, evidence, alerts, training, personnel, privacy, audit engagements, change requests, compliance calendar, search, risk, reports, settings/admin. | XL | R2 |
| 27 | No TUI dashboard/home screen | "Home" is remediations list. Should be a KRI dashboard with posture summary, alerts, overdue items. | L | R2 |
| 28 | No interactive TUI for creating/editing entities | TUI is read-only. Cannot create POA&Ms, findings, issues from TUI. | XL | R2 |
| 29 | CLI analytics have ZERO API endpoints | `compliance-views`, `security-posture`, `comply`, `correlate`, `search`, `reports` — ~60% of platform value is CLI-only. TUI/web frontends are blocked. | L | R2 |
| 30 | No API routers for incidents, changes, calendar, exceptions, privacy, access reviews | Entire CLI domains with no API coverage. | M | R2 |
| 31 | No pipeline data lineage tracking | Cannot trace control_result -> finding -> raw_event -> connector_run. No end-to-end lineage graph or lineage metadata per record. | L | R1 |
| 32 | No pipeline data quality validation layer | No checks for duplicates, null required fields, schema violations, out-of-range values. `schema_registry.py` exists but isn't wired into pipeline. | L | R1 |
| 33 | No pipeline observability/metrics export | No Prometheus/OTel metrics for throughput, latency, error rates, queue depth. No time-series for pipeline performance. | L | R1 |
| 34 | No incremental pipeline mode exercised in demo | `IncrementalTracker` exists but demo runs full-refresh only. Never demonstrated or tested. | M | R1 |
| 35 | 6 framework Rego policy dirs have only 1 stub | EU AI Act, FedRAMP, ISO 27701, ISO 42001, SEC Cyber — pipeline OPA stage evaluates nothing for these. | L | R3 |
| 36 | Assertion coverage at 23.5% (489/2,084 controls) | 76.5% fall to Tier 2 (AI) or remain `not_assessed`. Without AI, perpetually unassessed. | XL | R3 |
| 37 | No OSCAL Assessment Plan (SAP) export | FedRAMP requires SAP. AR references `/api/v1/assessment-plans/latest` which doesn't exist. | M | R3 |
| 38 | 3 frameworks missing OSCAL catalogs | NIST CSF 2.0, EU AI Act, SEC Cyber — can't export OSCAL for these. | M | R3 |
| 39 | No evidence document management (upload, version, tag, expire) | Every GRC platform has this. `evidence gaps` reports 747K/747K controls lack uploaded evidence. | L | R3 |

### Market Table Stakes (Every Competitor Has This)

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 40 | No evidence request workflow (PBC lists) | Auditor-to-control-owner request/response with deadlines, tracking, escalation. Required for active audit engagements. | L | R4 |
| 41 | No unified readiness-to-audit view | Score + timeline projection + prioritized gaps in one experience. "When are we audit-ready?" is the #1 buyer question. | M | R4 |
| 42 | No guided remediation wizard | Step-by-step fix flow with cloud console links. Gap between "you have a finding" and "you fixed it." | M | R4 |
| 43 | No policy template library + acknowledgment tracking | 100+ pre-written policies + employee-facing portal + tracked acknowledgment as evidence. | L | R4 |
| 44 | No access review campaign management | Periodic campaigns: create, assign to managers, track completion, certify, escalate overdue. SOC 2 CC6.1, ISO A.9.2.5. | M | R4 |
| 45 | No interactive dashboard builder | Drag-and-drop compliance widgets, save/share views. Every enterprise buyer expects personalized dashboards. | XL | R4 |
| 46 | No notification preferences engine | Per-user channel/frequency config for alerts. Users drown in alerts or get none. | M | R4 |
| 47 | No employee lifecycle automation | Onboarding/offboarding workflows triggered by HRIS events. Table stakes for SOC 2 CC6.2/CC6.3. | L | R4 |

---

## P2 — HARDENING (Limits Credibility / Competitive Gaps)

### Bugs / UX Issues

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 48 | `framework-diff` expects file paths, not framework IDs | Inconsistent with every other `-f` command. | S | R1 |
| 49 | `inheritance` requires undiscoverable system IDs | Demo seed doesn't advertise valid system IDs. | S | R1 |
| 50 | `risk` command doesn't accept `-f` directly | Must be `risk analyze -f`, not `risk -f` as DEMO.md suggests. | S | R1 |
| 51 | `issues` takes no `list` subcommand | `issues list` fails with "unexpected extra argument". Inconsistent with `poams`/`findings`. | S | R2 |
| 52 | `oscal ssp` uses positional arg, not `--framework` | Inconsistent with other commands that use `-f`. | S | R2 |
| 53 | `access-review list` shows 0/0 progress | Campaigns created but no review items within them. | S | R2 |
| 54 | `soa` only generates ISO 27001 | Should support `--framework` for SOC 2, NIST, etc. SoA is a universal audit artifact. | M | R2 |
| 55 | `training` group has no `list` command | Cannot list individual training records. | S | R2 |
| 56 | `bcp` group has no `list` command | Cannot list BCP plans directly. | S | R2 |
| 57 | `control-tests` group has no `list` command | Cannot list control test results directly. | S | R2 |
| 58 | `vendors` doesn't accept `list` subcommand | Inconsistent CLI UX. | S | R3 |

### Missing Features

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 59 | No pipeline DAG visualization | Stages are implicit. No visual dependency graph. Modern orchestrators (Dagster, Prefect) provide this. | M | R1 |
| 60 | No real-time streaming / webhook ingestion | All ingestion is pull-based. No webhook endpoint for push events (CloudTrail/GuardDuty/SNS). | L | R1 |
| 61 | No pipeline cost/resource tracking | No API call counts, data volume, or processing time per connector. | S | R1 |
| 62 | No lake partitioning management | No CLI for partition stats, rebalancing, or strategy configuration. | M | R1 |
| 63 | No SCD tracking wired into pipeline | `lake/scd.py` exists but unclear if used. Control status needs Type 2 SCD history. | L | R1 |
| 64 | No lake access controls / row-level security | Parquet files readable by anyone with filesystem access. No tenant isolation in lake. | M | R1 |
| 65 | No pipeline canary / smoke test | No `pipeline smoke-test` for quick health checks. | S | R1 |
| 66 | No pipeline schema evolution handling | `schema_registry` exists but not exercised on connector output changes. | M | R1 |
| 67 | No lake time travel queries | Iceberg registered but time travel not exposed in CLI. Can't query "SOC 2 posture 30 days ago." | L | R1 |
| 68 | No pipeline volume anomaly alerting | No alert when connector produces 0 or 10,000 findings instead of usual 100. | M | R1 |
| 69 | No `--export` for most entities | Only `findings` has export. Issues, POA&Ms, results, evidence, incidents need `export --format json/csv`. | M | R2 |
| 70 | No `--system` filter on most commands | Many support `--framework` but not `--system`. Essential for multi-system environments. | M | R2 |
| 71 | No real-time websocket streaming | `dashboard live` polls. No WebSocket API for live compliance events to web frontends. | L | R2 |
| 72 | No notification routing CLI | Can't route specific alert types to specific channels (critical -> PagerDuty, drift -> Slack). | M | R2 |
| 73 | No saved views/bookmarks in TUI | Can't save filtered views or quickly switch between them. | M | R2 |
| 74 | 9 DB models with no CLI | DeadLetterEntry, Asset, IPAllowlist, RiskDependency, BrandingConfig, SandboxEnvironment, DelegationGrant, ComplianceObligation, Tenant. | S each | R2 |
| 75 | No continuous evidence collection automation | Pipeline collects on-demand. No scheduled evidence refresh per control. | L | R3 |
| 76 | No evidence sufficiency scoring | Freshness exists but not "does this evidence actually prove the control?" | L | R3 |
| 77 | No compliance event outbound webhooks | No "AC-2 degraded, notify Slack/PagerDuty/ServiceNow" triggers. | M | R3 |
| 78 | No end-to-end audit program lifecycle | No schedule -> assign assessors -> track milestones -> collect -> review -> issue report -> track remediation flow. | XL | R3 |
| 79 | No FAIR risk quantification exposed via CLI/API | Engine exists but buried in code. Need `risk quantify --scenario` and API endpoint. | M | R3 |
| 80 | No control testing program demo data | `control-tests` commands exist but demo has no test data. Foundational for SOC 2 Type II. | M | R3 |
| 81 | No SSP narrative generation (Word/PDF) | OSCAL JSON only. FedRAMP requires human-readable SSP. Auditors review Word docs, not JSON. | L | R3 |
| 82 | No compliance score trending / historical analysis | `posture_snapshots` table empty. No CLI for score over time. Board reporting requires trend lines. | M | R3 |
| 83 | No customer-facing trust center UI | Trust portal API exists but no hosted trust center. Trust documents table empty. | L | R3 |
| 84 | No SIG/CAIQ questionnaire auto-fill from evidence | Vendor templates exist but no inbound questionnaire handling. | L | R3 |
| 85 | No data classification / DLP integration | `data_silos` model exists but no Macie/Purview/BigQuery DLP connectors. | M | R3 |
| 86 | No board reporting PDF export | `dashboard executive` is terminal-only. CISOs present to boards quarterly. | M | R3 |
| 87 | No GRC-as-Code workflow (git-native compliance) | Framework YAML + Rego exist but no PR-reviewed, CI-validated compliance workflow. | L | R3 |

### Market Differentiators

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 88 | Compliance-as-code packaging | `warlock init`, CI gates, PR-level compliance analysis. Warlock's unique advantage vs. SaaS competitors. | L | R4 |
| 89 | CMDB-driven authorization boundaries | Auto-derive FedRAMP boundaries from asset inventory. ServiceNow's key advantage. | L | R4 |
| 90 | Attack path to compliance mapping | Wiz/Orca attack paths -> control impact. Bridge security and compliance posture. | M | R4 |
| 91 | Regulatory intelligence engine | AI-powered monitoring, classification, auto gap analysis of regulatory changes. | L | R4 |
| 92 | cATO engine with ConMon deliverables | Full continuous authorization loop: monitor -> detect change -> scope assessment -> package. | XL | R4 |
| 93 | Supply chain compliance (C-SCRM) | SBOM -> compliance mapping, supplier flow-down, SLSA/VEX/EPSS scoring. | L | R4 |
| 94 | Predictive risk modeling | Time-series forecasting, control failure prediction, risk trend extrapolation. | L | R4 |
| 95 | Compliance visualization library | Heatmaps, trend charts, posture gauges, sunbursts, network graphs, Sankey, Gantt. | L | R4 |
| 96 | Text-to-SQL natural language analytics | NL -> SQL -> results -> chart. Follow-up queries in context. Explain mode. | L | R4 |
| 97 | Custom report builder | Drag-and-drop, template library, data binding, export, scheduling, version history. | XL | R4 |
| 98 | Auditor self-service analytics portal | Read-only portal, query, sampling, evidence search, workpaper export. | L | R4 |
| 99 | Compliance velocity metrics | MTTC, gap closure rate, compliance debt, evidence freshness decay curves. | M | R4 |
| 100 | Anomaly detection improvements | Baseline learning, contextual, multi-dimensional, explainable, feedback loop. | M | R4 |
| 101 | Lake data lineage visualization | Interactive graph: raw event -> finding -> mapping -> result -> posture. Impact analysis. | M | R4 |
| 102 | Lake retention tiering | Hot/warm/cold/delete with retention policies per data classification. | M | R4 |

---

## P3 — NICE-TO-HAVE (Future Roadmap)

| # | Issue | Detail | Effort | Source |
|---|-------|--------|--------|--------|
| 103 | No pipeline warm-up / pre-flight check | Verify credentials and API reachability before full pipeline run. | S | R1 |
| 104 | No lake GC reporting | `lake maintenance` runs but doesn't report what was cleaned up. | S | R1 |
| 105 | No pipeline semantic diff | `pipeline compare` shows counts, not which controls/findings changed. | M | R1 |
| 106 | No lake metadata search | Can't search "which tables contain PII" or "zones with data >90 days old." | M | R1 |
| 107 | No pipeline SLA tracking | No "connector X must complete in 5 min" or "all connectors every 24h" alerting. | M | R1 |
| 108 | No `warlock version` command | Must use `python -c "import warlock; ..."`. Should be top-level CLI. | S | R2 |
| 109 | No `warlock doctor` diagnostic | No single command to check DB, OPA, AI, disk, lake, migration status. | M | R2 |
| 110 | No shell tab completion | Click supports `--install-completion` natively. | S | R2 |
| 111 | No CLI progress bars for long operations | `risk analyze` and `collect` run without progress indication. | S | R2 |
| 112 | No API rate limit headers | `X-RateLimit-Limit/Remaining/Reset` not exposed. Clients can't self-throttle. | S | R2 |
| 113 | No API versioning strategy | All under `/api/v1` with no v2 migration path or deprecation headers. | M | R2 |
| 114 | No GraphQL subscriptions | Schema exists but no real-time subscription support. | L | R2 |
| 115 | No TUI theming/configuration | Single theme, no light/dark toggle. | S | R2 |
| 116 | No TUI risk visualization | FAIR Monte Carlo loss exceedance curves would be impactful as TUI charts. | L | R2 |
| 117 | No webhook event catalog documentation | Webhooks can be registered but no documented catalog of trigger event types. | S | R2 |
| 118 | No offline/air-gapped deployment docs | Important for CMMC/FedRAMP. Warlock runs locally but isn't packaged for it. | S | R2 |
| 119 | No AI-powered SSP narrative generation | AI assesses but doesn't generate "how this control is implemented" prose. | M | R3 |
| 120 | No compliance benchmarking | No peer comparison capability. | XL | R3 |
| 121 | No regulatory change feed integration | `RegulatoryChangeManager` requires manual input. No RSS/API feed. | M | R3 |
| 122 | No SBOM/supply chain risk integration | No CycloneDX/SPDX ingestion. No VEX support. | L | R3 |
| 123 | No quantum readiness assessment | No crypto inventory, no PQC migration tracking. NIST PQC standards are finalized. | M | R3 |
| 124 | No SOC 2 Type II observation period tracking | No concept of "controls effective continuously for 3-12 months." | M | R3 |
| 125 | Multi-language / localization | English-only. Blocks international enterprise adoption. | XL | R4 |
| 126 | Industry benchmarking data | Requires sufficient deployment scale. Opt-in anonymous aggregation. | L | R4 |
| 127 | SOX compliance module | ITGC + business process controls. New framework + assertions. | XL | R4 |
| 128 | ESG/sustainability reporting | New framework. | L | R4 |
| 129 | No-code workflow builder | LogicGate-style visual GRC process design. | XL | R4 |
| 130 | Auto-remediation engine | Drata Autopilot equivalent: auto-fix cloud misconfigs with safety controls. | XL | R4 |
| 131 | Mobile app | Status, approvals, notifications on the go. | XL | R4 |
| 132 | Endpoint agent | macOS/Windows/Linux disk encryption, screen lock, patches. Swift/Go/Rust codebase. | XL | R4 |
| 133 | AI governance module | Model inventory, EU AI Act risk tiers, bias monitoring, transparency docs. | L | R4 |
| 134 | Privacy engineering automation | Auto data flow diagrams, PIA pre-population, consent receipt management. | L | R4 |
| 135 | Air-gapped deployment packaging | Single container, offline frameworks, STIG-hardened config. | M | R4 |

---

## Summary

| Priority | Bugs | Missing Features | Market Gaps | Total |
|----------|------|-----------------|-------------|-------|
| P0 | 8 | 3 | — | **11** |
| P1 | 14 | 14 | 8 | **36** |
| P2 | 11 | 29 | 15 | **55** |
| P3 | — | 19 | 14 | **33** |
| **Total** | **33** | **65** | **37** | **135** |

The **engineering hotfix queue** at the top of this file is separate from these 135 audit rows.

### By Effort

| Effort | Count | Est. Person-Days |
|--------|-------|-----------------|
| S (<1 day) | 38 | ~38 |
| M (1-3 days) | 47 | ~94 |
| L (3-5 days) | 33 | ~132 |
| XL (1+ week) | 17 | ~119 |
| **Total** | **135** | **~383** |

### Warlock's Existing Strengths (Do NOT Rebuild)

1. **Pipeline architecture** — 4-stage hash-chained pipeline is more rigorous than any competitor
2. **Connector breadth** — 351+ connectors rivals Vanta (~300) and exceeds most others
3. **Framework coverage** — 14 frameworks with 2,084 controls and crosswalks
4. **Data lake** — DuckDB + Parquet + Iceberg is a genuine engineering advantage
5. **OSCAL support** — Deterministic OSCAL export is unique in the market
6. **Multi-tier assessment** — Assertions -> AI -> OPA -> inheritance beats competitors' binary pass/fail
7. **Risk quantification** — FAIR + Monte Carlo exceeds most competitors' qualitative heatmaps
8. **CLI depth** — 100+ commands across 70+ modules — no competitor has a CLI at all
9. **TUI** — Interactive terminal dashboard is unique in the market
10. **Compliance-as-code DNA** — OPA/Rego + Terraform + policy-as-code — no competitor has this
11. **GDPR engineering** — Anonymization-based erasure preserves audit chain (not deletion)
12. **AI integration** — Multi-provider with conversation, RAG, questionnaire auto-fill

### Top 10 Priority Actions

1. **Fix 8 P0 bugs** (items 1-8) — all S/M effort, blocks demo credibility
2. **Seed 18 empty demo tables** (item 21) — Rule 8 violations across the board
3. **Add CSV output format** (item 9) — auditors need this immediately
4. **Expose CLI analytics via API** (item 29) — 60% of platform value is CLI-only
5. **Fix OSCAL SSP required fields** (item 23) — blocks FedRAMP compliance claims
6. **Build evidence request workflow** (item 40) — table stakes for audit engagements
7. **Add unified readiness-to-audit view** (item 41) — #1 buyer question
8. **Expand TUI to 15+ screens** (item 26) — TUI is a differentiator, needs coverage
9. **Fix audit trail completeness** (item 25) — <0.01% coverage is a red flag
10. **Add guided remediation wizard** (item 42) — bridge "finding" to "fixed"
