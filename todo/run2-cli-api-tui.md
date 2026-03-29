# Warlock Audit: CLI, API, and TUI — Run 2

Audit date: 2026-03-29
Database: demo seed (351 connectors, ~14,707 findings, 500K control results)

---

## Section 1: What Works (Verified With Real Data)

### CLI — Core Pipeline & Compliance (all show real data)
- `dashboard posture` — 14 frameworks, compliance rates, coverage stats
- `dashboard executive` — board-level summary with KRI, issues, POA&Ms
- `dashboard operations` — connector health, pipeline status, 702 runs in 24h
- `dashboard security` — vulnerability counts, MTTR
- `findings list` — 50 findings displayed, severity/type/source columns
- `findings show` — detail view works, supports omitted ID (shows latest)
- `findings stats` — aggregate stats by severity/source
- `findings search` — full-text search by title
- `findings export` — JSON/CSV export
- `findings aging` / `findings sla` / `findings timeline` / `findings trending`
- `frameworks list` — 14 frameworks with family/control counts
- `results` — control results with framework/status/assessor
- `connectors list` — 351 connectors, all success status
- `pipeline status` — recent pipeline runs with duration/events
- `assertions` — 103 assertions with control binding counts
- `conmon status` — continuous monitoring status per framework
- `comply readiness-score soc2` — 50/100 with breakdown components
- `comply maturity-model` — Level 2/5 maturity assessment
- `comply debt` — overdue POA&Ms, stale attestations, stale evidence
- `comply quick-wins` — 334 candidates, prioritized by effort/impact
- `comply benchmark` / `comply continuous-compliance` / `comply regression-check`
- `correlate gap-analysis soc2` — non-compliant controls, source coverage
- `correlate blast-radius` / `correlate coverage-matrix` / `correlate orphan-controls`
- `risk analyze -f soc2` — FAIR Monte Carlo, 46 scenarios, ALE/VaR95/VaR99
- `risk cache-stats` / `risk precompute`
- `reports executive -f soc2` — posture score, control counts, issues, findings
- `reports kri` — key risk indicators with threshold breach detection
- `reports board` — board-level GRC summary
- `reports connector-health` / `reports kpi` / `reports trend`
- `oscal ssp soc2` — generates OSCAL SSP JSON file
- `oscal assessment-results` / `oscal poam` / `oscal component-definition`
- `oscal catalogs list` / `oscal profiles`
- `search full-text -q mfa` — 58 results across findings/controls/issues
- `search faceted` / `search recent` / `search palette`

### CLI — Governance & Workflow (all show real data)
- `poams` / `poam list` — 26 POA&Ms with severity/status/due dates
- `issues` — 50+ issues with framework/control/priority/assignee
- `attestations list` — 4 attestations in draft/submitted/approved states
- `evidence list` — evidence records with freshness indicators
- `evidence-requests` — 7 evidence requests with status
- `incidents list` — 50 incidents across multiple classifications
- `changes list` — 4 change requests in various states
- `exceptions list` — 3 active policy exceptions with expiry dates
- `calendar list` — 4 compliance deadlines (audits, reviews, assessments)
- `access-review list` — 2 campaigns (active, completed)
- `audit engagement list` — 2 engagements (NIST, SOC 2) with auditor info
- `audit-trail list` — 92 entries with hash-chained integrity
- `training status` — 6% completion rate, department breakdown
- `remediate list` — 15 remediations in various lifecycle states
- `alerts list` — 16 alerts (EDR behavioral, DLP, control drift, etc.)
- `compensating-controls` — 20 compensating controls with effectiveness scores
- `risk-acceptances` — 14 risk acceptances in active/requested/revoked states
- `policy list` — 8 operational policies (cadence, classification, SLA, etc.)

### CLI — Privacy (all show real data)
- `privacy dsar list` — 3 DSARs in open/in_progress/overdue states
- `privacy breach list` — 3 breaches (phishing, S3 exposure, stolen laptop)
- `privacy transfers list` — 3 cross-border transfers (SCCs, BCRs, EU-US DPF)
- `privacy ropa` — 88 processing activities generated from data inventory
- `privacy data-map` — 88 data silos with PII/PHI flags, encryption status

### CLI — Security Posture & Analytics (all show real data)
- `vulns dashboard` — 2,843 vulns, severity breakdown, top sources
- `vulns sla-breach` / `vulns aging` / `vulns by-scanner` / `vulns trends`
- `security-posture encryption-status` — encryption coverage by resource type
- `security-posture patch-compliance` — SLA compliance by severity
- `security-posture ttp-mapping` — 8 MITRE ATT&CK techniques, 3 with gaps
- `security-posture network-exposure` / `security-posture firewall-rules`
- `compliance-views pareto` — top 20 failure families with cumulative %
- `compliance-views by-org-unit` — compliance by system profile
- `compliance-views cato-dashboard` — ATO health per system
- `compliance-views ai-confidence` — 10 AI assessments, mean 0.817
- `compliance-views usage-stats` — platform usage metrics
- `compliance-views platform-health` — connector/pipeline health
- `soa` — ISO 27001 Statement of Applicability, 93 controls
- `sod conflicts` — 4 SoD rules with violation counts

### CLI — Infrastructure & Integration
- `lake status` — 1,763 files, 76.4 MB across raw/enrichment/curated zones
- `terraform modules` / `terraform compliance` / `terraform validate`
- `policies` — OPA/Rego policy browsing and validation
- `integrations list` — shows 12 available integration types
- `collaboration` / `automation` / `lifecycle` — workflow commands registered

### CLI — Data Models With Coverage
- `systems` — 10 system profiles (note: duplicates exist, see Section 2)
- `personnel` — 50 personnel records with HR/IdP/training status
- `data-silos` — 50+ data silos with classification/encryption
- `system-dependencies` — 12 inter-system dependencies
- `change-events` — 50+ CloudTrail-sourced change events
- `compliance-drifts` — 20 drift events with direction indicators
- `control-inheritances` — 50+ inheritance mappings
- `policy-overrides` — 3 active overrides
- `external-auditors` — 2 auditors (Deloitte, EY)
- `questionnaires` — 2 vendor questionnaires
- `posture-snapshots` — 50+ historical snapshots

### API — Verified Endpoint Coverage (205 endpoints across 17 routers)
- **Compliance router**: frameworks, findings, results, connectors, posture, drift, effectiveness, dashboard summary, topology (17 endpoints)
- **Governance router**: issues (CRUD + transitions + comments), attestations (lifecycle), engagements (CRUD + evidence + package), POA&Ms (CRUD + transitions), compensating controls, risk acceptances, SoD analysis
- **Admin router**: users (CRUD), systems (CRUD + posture + findings), personnel (list + flags + sync), retention (report + purge + legal holds), data silos (CRUD + discover), audit trail (list + verify), GDPR (export + erase)
- **Risk router**: FAIR analysis, vendor risk, policy coverage/gaps, audit simulation, framework diff, impact check
- **Alerts router**: CRUD + acknowledge + resolve + dismiss
- **Remediation router**: 5-stage lifecycle (open -> assigned -> in_progress -> verification -> closed) + generate + apply + re-scan
- **Auth router**: login, MFA verify, refresh, register, API keys (CRUD), me, change-password, logout
- **Pipeline router**: collect, status, verify-chain, scheduler (status/start/stop)
- **Export router**: OSCAL export, questionnaire templates, questionnaires (CRUD + scoring)
- **Evidence router**: submit (2 separate routers for Terraform and general evidence)
- **Trust portal router**: request-access, status, documents, download
- **Webhooks router**: CRUD + test + Jira webhook
- **AI router**: status, models, configure, reason, converse, conversations, audit
- **Health router**: health, health/live, health/ready
- **Resources router**: assets, vendors, personnel, data silos, system dependencies, control inheritances, change events, pipeline runs, saved queries, watch subscriptions, escalation policies, legal holds, evidence requests, questionnaire templates, questionnaires
- **SCIM router**: RFC 7643/7644 user provisioning
- **SSO router**: OIDC flows for Okta, Azure AD, Google, generic providers
- **GraphQL**: 414-line schema (strawberry-based)

### TUI — 7 Screens Registered
- Remediations (home screen)
- Findings
- Controls
- POA&M
- Pipeline
- Frameworks
- Vendors
- Command palette (Ctrl+K)
- Sidebar navigation with keyboard shortcuts (1-7, q)

---

## Section 2: What's Broken (Crashes, Empty Output, Wrong Data)

### P0 — Critical (Blocks Demo / Audit)

| ID | Issue | Detail |
|----|-------|--------|
| B-001 | `users list` shows 4 users but earlier run showed "No users found" | **Inconsistent**: first invocation returned empty, second returned 4 users. Possible session/import ordering issue — the `users list` command may fail if called before certain modules initialize. Needs investigation. | P0 | S |
| B-002 | `poam list` returns "No POA&Ms found" but `poams` shows 26 | Two separate commands for the same entity: `poam list` (from poam_cmd.py) and `poams` (from model_cmds.py) return different results. The `poam list` command likely queries with a filter that excludes all seeded POA&Ms. | P0 | S |
| B-003 | Duplicate system profiles in `systems` output | Shows 10 rows but only 5 unique systems — each system appears twice. Demo seed is creating duplicates on re-run. The `make reset` flow should be idempotent. | P0 | M |
| B-004 | `reports pdf` crashes with "reportlab is required" | PDF generation is a core demo feature but the dependency is missing from dev install. Either add to `[dev]` extras or gracefully degrade. | P0 | S |

### P1 — High (Incorrect Data or Missing Demo Seed Coverage)

| ID | Issue | Detail |
|----|-------|--------|
| B-005 | `watch-subscriptions` returns "No watch subscriptions found" | Model exists, API exists, but no demo seed data. Rule 8 violation. | P1 | S |
| B-006 | `escalation-policies` returns "No escalation policies found" | Model exists, API exists, but no demo seed data. Rule 8 violation. | P1 | S |
| B-007 | `embeddings` returns "No embeddings found" | Model exists but no demo seed data. Understandable if AI-only, but should show something with WLK_AI_ENABLED=false. | P1 | S |
| B-008 | `integrations list` shows "No integrations configured" | Demo should show at least one configured integration (e.g., Jira, Slack) to demonstrate the feature. | P1 | S |
| B-009 | `vendors` command runs vendor risk scorer, creates new findings on every invocation | Running `vendors` is a side-effect-heavy operation that mutates the database — creates new vendor risk findings each time. A read-only list command should not write data. | P1 | M |
| B-010 | `cato-dashboard` shows 0 controls and 0.0% score for most systems | System-to-control mapping is incomplete — only 2 of 10 system profiles have any control results linked. The remaining 8 show zeroes. | P1 | M |
| B-011 | `training` group has no `list` command | Cannot list individual training records. Only aggregate views (status, campaigns, overdue, report). Personnel training data is only viewable via `personnel`. | P1 | S |
| B-012 | `bcp` group has no `list` command | Cannot list BCP plans directly. Only assessment views (bia, backup-status, dr-readiness, etc.). | P1 | S |
| B-013 | `control-tests` group has no `list` command | Cannot list control test results directly. Only schedule/gaps/due/history views. | P1 | S |

### P2 — Medium (UX Issues, Inconsistencies)

| ID | Issue | Detail |
|----|-------|--------|
| B-014 | `issues` takes no subcommand but does not accept `list` as argument | `issues list` fails with "Got unexpected extra argument". Uses `invoke_without_command=True` pattern but unlike `poams`/`findings`, does not have a `list` subcommand. Inconsistent UX. | P2 | S |
| B-015 | `oscal ssp` uses positional argument, not `-f`/`--framework` flag | Inconsistent with `comply readiness-score`, `reports executive -f`, etc. which all use `-f`. | P2 | S |
| B-016 | `access-review list` shows 0/0 progress for both campaigns | Progress tracking shows no items reviewed — demo seed creates campaigns but no review items within them. | P2 | S |
| B-017 | `soa` only generates ISO 27001 SoA | Should support `--framework` flag for SOC 2, NIST, etc. Statement of Applicability is a universal audit artifact. | P2 | M |

---

## Section 3: What's Missing (Gaps vs Modern GRC Platforms)

### P0 — Critical Gaps

| ID | Gap | Detail | Effort |
|----|-----|--------|--------|
| G-001 | No CSV output format | Global `--output-format` only supports `table` and `json`. Modern GRC platforms must export to CSV for auditor handoff, Excel import, and SIEM integration. Every list command should support `--format csv`. | M |
| G-002 | No `--format` flag on individual commands | While `--output-format` exists globally, individual commands (findings list, issues, results, etc.) do not have local `--format` overrides. Auditors need per-command export control. | M |
| G-003 | No bulk finding import via CLI | `ingest` command exists for JSON webhook, but there is no `findings import` or `bulk import` for CSV/JSON batch import of findings from external scanners. | L |
| G-004 | No role/permission management CLI | `users list/create` exists but there is no CLI for managing roles, permissions, or RBAC policies. All role assignments must happen via direct DB or API. | M |

### P1 — High Priority Gaps

| ID | Gap | Detail | Effort |
|----|-----|--------|--------|
| G-005 | TUI missing screens for 80% of entities | Only 7 TUI screens exist (remediations, findings, controls, POA&M, pipeline, frameworks, vendors). Missing: incidents, evidence, alerts, training, personnel, privacy, audit engagements, change requests, compliance calendar, search, risk analysis, reports, settings/admin. A modern GRC TUI needs at least 15 screens. | XL |
| G-006 | No TUI dashboard/home screen | The "home" screen is the remediations list. Should be a dashboard with KRI tiles, compliance posture summary, recent alerts, overdue items — the single most important screen for daily GRC operations. | L |
| G-007 | No interactive TUI for creating/editing entities | TUI is read-only. Cannot create findings, POA&Ms, issues, or remediations from the TUI. Modern TUI apps (like `lazygit`) support full CRUD with modal dialogs. | XL |
| G-008 | No API endpoint for compliance-views analytics | All `compliance-views` commands (pareto, by-org-unit, cato-dashboard, forecast, peer-benchmark, etc.) are CLI-only. No corresponding API endpoints. The TUI and web frontends cannot access this data. | L |
| G-009 | No API endpoint for security-posture analysis | All `security-posture` commands (encryption-status, patch-compliance, ttp-mapping, network-exposure, etc.) are CLI-only. No API coverage. | L |
| G-010 | No API endpoint for `comply` analytics | readiness-score, maturity-model, quick-wins, debt, regression-check — all CLI-only. These are the most valuable compliance automation features and need API exposure. | L |
| G-011 | No API endpoint for `correlate` commands | gap-analysis, blast-radius, coverage-matrix, orphan-controls — CLI-only. | L |
| G-012 | No API endpoint for `search` commands | full-text, faceted, fuzzy, recent — CLI-only. The TUI and web frontends need search APIs. | M |
| G-013 | No API endpoint for `reports` generation | executive, board, compliance, kri, kpi, trend, sla — all CLI-only. API should support on-demand report generation with async delivery. | L |
| G-014 | No API endpoint for training/BCP/control-tests | These entire CLI domains have no API coverage at all. | L |
| G-015 | No API endpoint for incidents | CLI has full incident lifecycle but no API router for incidents. | M |
| G-016 | No API endpoint for changes/change requests | CLI has full change management but no API router. | M |
| G-017 | No API endpoint for calendar | Compliance calendar is CLI-only. | S |
| G-018 | No API endpoint for exceptions | Policy exceptions are CLI-only. | S |
| G-019 | No API endpoint for privacy commands | DSARs, breaches, transfers, ROPA, data map — all CLI-only despite being critical for GDPR compliance. | M |
| G-020 | No API endpoint for access reviews | CLI has full campaign lifecycle but no API router. | M |

### P2 — Medium Priority Gaps

| ID | Gap | Detail | Effort |
|----|-----|--------|--------|
| G-021 | No OpenAPI schema customization | FastAPI auto-generates OpenAPI docs but docs_url is disabled in production. No custom API documentation site or Redoc customization. | S |
| G-022 | No CLI command for API key rotation | Can create/delete API keys via API but no CLI command for key management. | S |
| G-023 | No CLI `export` for most entities | Only findings has `export` subcommand. Issues, POA&Ms, results, evidence, incidents should all support `export --format json/csv`. | M |
| G-024 | No `--system` filter on most commands | Many commands support `--framework` filter but not `--system` filter. In multi-system environments, filtering by system profile is essential. | M |
| G-025 | No real-time streaming/websocket support | `dashboard live` command exists but uses Rich Live polling. No websocket API for real-time compliance event streaming to web frontends. | L |
| G-026 | No notification preferences/routing CLI | Can configure integrations but no CLI for routing specific alert types to specific channels (e.g., critical alerts to PagerDuty, drift alerts to Slack). | M |
| G-027 | No saved views/bookmarks in TUI | Cannot save a filtered view (e.g., "SOC 2 critical findings") and quickly switch between saved views. | M |
| G-028 | No TUI theming/configuration | Single theme.tcss with no user customization. No light/dark mode toggle. | S |
| G-029 | No CLI for workpaper management | Workpaper model exists, audit workpapers are seeded, but no dedicated CLI commands. Only accessible via `audit workpapers`. | S |
| G-030 | No CLI for asset management | Asset model exists, API endpoints exist (GET /assets, GET /assets/{id}), but no dedicated CLI group. Assets are only visible as data within findings. | S |
| G-031 | No CLI for dead letter queue | DeadLetterEntry model exists but no CLI to inspect or replay failed pipeline events. | S |
| G-032 | No CLI for sandbox environments | SandboxEnvironment model exists but no CLI management. | S |
| G-033 | No CLI for delegation grants | DelegationGrant model exists but no CLI for managing delegated access. | S |
| G-034 | No CLI for compliance obligations | ComplianceObligation model exists but no CLI for tracking regulatory obligations. | S |
| G-035 | No CLI for IP allowlist management | IPAllowlistEntry model exists but no CLI. Admin API only. | S |
| G-036 | No CLI for risk dependencies | RiskDependency model exists but no CLI. Only `system-dependencies` covers system-level deps. | S |
| G-037 | No CLI for branding configuration | BrandingConfig model exists (white-label) but no CLI management. | S |

### P3 — Nice to Have / Future Roadmap

| ID | Gap | Detail | Effort |
|----|-----|--------|--------|
| G-038 | No mobile-friendly API design | API responses include full entity objects. No field selection (GraphQL partially addresses this). No summary/compact response modes for mobile bandwidth. | L |
| G-039 | No webhook event catalog | Webhooks can be registered but there is no documented catalog of event types that trigger webhooks. | S |
| G-040 | No CLI tab completion | No shell completion script generation (`--install-completion`). Click supports this natively with `click.shell_completion`. | S |
| G-041 | No CLI progress bars for long operations | `risk analyze` and `collect` run without progress indication. Should use Rich progress bars for Monte Carlo simulations and multi-connector collection. | S |
| G-042 | No offline/disconnected mode documentation | No guidance on running Warlock air-gapped (no internet, no AI, no external connectors). Important for CMMC/FedRAMP environments. | S |
| G-043 | No multi-language support | All CLI output, reports, and UI text is English-only. GDPR and international compliance work requires at least the ability to generate reports in the local language. | XL |
| G-044 | No `warlock doctor` diagnostic command | No single command to check system health: DB connectivity, OPA availability, AI service status, disk space, lake integrity, migration status. | M |
| G-045 | No `warlock version` command | Must use `python -c "import warlock; print(warlock.__version__)"`. Should be a top-level CLI command. | S |
| G-046 | No TUI screen for risk analysis visualization | FAIR Monte Carlo results with loss exceedance curves would be highly impactful as a TUI chart (using textual-plotext or similar). | L |
| G-047 | No API rate limit visibility | Rate limits are enforced but not exposed in response headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset). Clients cannot self-throttle. | S |
| G-048 | No API versioning strategy | All endpoints are under /api/v1 but there is no v2 migration path, deprecation header support, or versioning documentation. | M |
| G-049 | No GraphQL subscriptions | GraphQL schema exists but no subscription support for real-time updates. | L |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| CLI commands/groups verified working | 100+ |
| CLI commands showing empty data (Rule 8 violations) | 5 |
| CLI commands with crashes/errors | 2 |
| CLI commands with wrong/inconsistent behavior | 3 |
| API endpoints | 205 |
| API routers | 17 |
| TUI screens | 7 |
| DB models | 55 |
| DB models with no CLI | 9 (DeadLetterEntry, Asset, IPAllowlistEntry, RiskDependency, BrandingConfig, SandboxEnvironment, DelegationGrant, ComplianceObligation, Tenant) |
| DB models with no API | varies (most covered via resources router) |
| Total P0 items | 8 (4 broken + 4 missing) |
| Total P1 items | 21 (9 broken + 12 missing) |
| Total P2 items | 21 (4 broken + 17 missing) |
| Total P3 items | 12 |
| **Total items** | **62** |

### Top 5 Priority Actions

1. **Fix duplicate system profiles** (B-003) — breaks demo credibility
2. **Fix `poam list` vs `poams` inconsistency** (B-002) — confusing for users
3. **Add CSV output format** (G-001) — auditors need this immediately
4. **Seed demo data for empty models** (B-005 to B-008) — Rule 8 violations
5. **Add API endpoints for CLI-only analytics** (G-008 to G-020) — TUI and web clients are blocked
