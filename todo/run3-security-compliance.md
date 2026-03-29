# Run 3: Security, Compliance, and Export Audit

Audited: 2026-03-29
Database: warlock.db (seeded demo data)
Method: Systematic testing of OPA, OSCAL, audit trail, ABAC, workflows, assessment tiers, and framework coverage against the running demo database.

---

## Section 1: What Works (Verified)

### OPA Policy Engine
- **730/730 Rego tests pass** across all framework policy directories
- `opa check policies/` clean (no errors, no warnings)
- 341 policy files + 335 test files = near-100% test coverage for policy logic
- Policies are actually wired into the pipeline via `OPAComplianceEvaluator` in `orchestrator.py` (Stage 5)
- Framework coverage by policy count: NIST 800-53 (142), ISO 27001 (93), CMMC (25), HIPAA (20), SOC 2 (13), UCF (12), PCI DSS (12), GDPR (10), Terraform (9)

### OSCAL Export
- SSP export produces valid OSCAL 1.1.2 JSON with proper `system-security-plan` envelope
- SSP includes: metadata, import-profile, system-characteristics, system-implementation (1721 components), control-implementation (1233 implemented-requirements with statements)
- POA&M export produces valid OSCAL with 73,427 poam-items
- Assessment Results export works (339,458 findings + observations for NIST 800-53)
- Component Definition export available per-framework
- `warlock oscal validate` confirms structural validity
- `warlock oscal audit-package` bundles AR + SSP + POA&M + component-definition + manifest into a single directory (verified for SOC 2)
- 11 OSCAL catalog packages exist with real content (not stubs) -- verified file sizes range from 15KB to 583KB

### Audit Trail
- Hash chain verification works: `warlock audit-trail verify` confirms 93 entries intact
- Tamper detection scan passes
- 93 audit entries across 29 entity types covering: control assessment, finding creation, evidence collection, login/logout, change requests, DSAR, breaches, personnel, webhooks, etc.
- Stats, search, timeline, export, retention-status commands all functional

### Assessment Engine (Tier 1 + Tier 2 + Inheritance)
- 103 registered assertion functions with 489 control bindings across 2,084 controls
- Tier 1 (deterministic assertions) running in pipeline -- 23.5% coverage of all controls
- Tier 2 (AI reasoning) wired and functional with confidence floor (0.7) and inline/batch modes
- Parent-to-child control inheritance implemented (AC-2 -> AC-2(1), AC-2(2), etc.)
- Multiple assertions per control supported (list-based bindings)
- Assessment stats show realistic pass/fail distribution across assertions

### Authentication and Authorization
- JWT + API key dual auth with bcrypt (preferred) / PBKDF2-SHA256 (fallback) password hashing
- `require_permission()` dependency used across all non-public API routes (verified: admin 44/43, compliance 18/17, governance 40/39, etc.)
- 4-role RBAC: admin, auditor, owner, viewer with distinct permission sets
- API key scopes intersected with role permissions (least privilege)
- Timing oracle prevention on login (S-13 dummy hash)
- Account lockout protection
- MFA support (TOTP)
- Rate limiting per endpoint with configurable limits
- Security headers: X-Content-Type-Options, X-Frame-Options, HSTS, CSP

### OPA Policy Gate (API)
- OPA policy gate wired into API middleware (`app.py` line 124)
- Fail-closed by default (`opa_fail_mode = "closed"`)
- Health endpoints correctly bypassed

### Workflows
- POA&M state machine with validated transitions (draft -> open -> in_progress -> remediated -> verified -> completed, plus risk_accepted/cancelled from any state)
- 26 open POA&Ms in demo with milestones, deviations, bulk operations
- Risk acceptance workflow with 14 records across multiple frameworks and statuses (active, requested, revoked)
- 20 compensating controls with effectiveness scores
- GDPR erasure anonymizes via HMAC (never deletes) -- preserves referential integrity
- GDPR DSAR lifecycle (create, fulfill, escalate, overdue tracking)
- Privacy breach management, ROPA generation, cross-border transfer records
- Vendor risk scoring from findings (59 vendor profiles built from securityscorecard data)
- Incident lifecycle with 50 incidents, playbooks, responders, post-mortem reports
- cATO workflow for FedRAMP continuous authorization
- Regulatory change management with impact assessment
- Evidence vault supporting S3, GCS, and local backends

### Framework Coverage
- 14 frameworks with YAML definitions + controls
- Crosswalk mappings functional (verified NIST 800-53 -> SOC 2)
- Compliance coverage dashboard shows all 14 frameworks with pass rates
- Control effectiveness tracking with MTTR and drift counts
- Monte Carlo compliance forecasting with P10/P50/P90 confidence intervals
- Continuous monitoring status across all frameworks

### Data Pipeline
- 707 connector runs, 2,142 raw events, 14,766 findings, 747,704 control results
- 356 connectors registered
- Pipeline orchestrator handles collect -> normalize -> map -> assess -> OPA evaluate
- Hash-chained lineage from raw event through control result

### API
- 224 routes across 16 routers
- Trust portal (intentionally public, separate auth model)
- Multi-tenancy via ContextVar with auto-applied tenant filters

---

## Section 2: What's Broken (Bugs, Errors, Security Issues)

### P0 - Critical

#### BUG-01: `warlock evidence gaps` crashes with Rich markup error
- **File**: `/Users/jsn/warlock/warlock/cli/evidence_cmd.py`, line 620
- **Error**: `rich.errors.MarkupError: closing tag '[/]' at position 14 has nothing to close`
- **Root cause**: `f"[{status_style}]{r.status}[/]"` when `status_style` is empty string (for statuses like `not_assessed` that don't match the style dict), this becomes `[]{r.status}[/]` which is invalid Rich markup
- **Fix**: Use the documented anti-pattern fix: `f"[{style}]{text}[/{style}]" if style else escape(text)`
- **Impact**: Cannot view evidence gaps -- critical for audit prep
- **Effort**: S

### P1 - High

#### BUG-02: OSCAL SSP missing required fields per NIST OSCAL 1.1.2 spec
- **Missing**: `security-impact-level`, `status` (system authorization status), `date-authorized`, `responsible-parties`
- **File**: `/Users/jsn/warlock/warlock/export/oscal.py`
- **Impact**: SSP would fail NIST OSCAL schema validation and FedRAMP automated checks. `security-impact-level` is REQUIRED for FedRAMP SSPs. `status.state` is REQUIRED per OSCAL SSP model.
- **Effort**: M

#### BUG-03: OSCAL SSP `import-profile` uses internal UUID reference instead of resolvable href
- **Current**: `"href": "#967a8853-2bb7-4e85-9fc2-c27ec721cace"` (fragment reference to nowhere)
- **Expected**: Should reference the actual OSCAL profile JSON (e.g., `./profile.json` or the catalog URI)
- **Impact**: OSCAL tools cannot resolve the profile reference; breaks SSP-to-catalog traceability
- **Effort**: S

#### BUG-04: Demo seed does NOT create users in the database
- **Evidence**: `grep -c "create_user\|User(" scripts/demo_seed.py` returns 0, yet `users` table has 4 rows
- **Impact**: Users exist but were likely created by a previous ad-hoc run. Fresh `make reset` may not create them, breaking API auth testing in demo. Needs verification and explicit user seeding.
- **Effort**: S

#### SEC-01: Audit trail has only 93 entries for a demo with 14,766 findings and 747,704 control results
- **Evidence**: `warlock audit-trail stats` shows 93 entries total
- **Gap**: Pipeline operations (finding creation, control result assessment, connector runs) are NOT generating audit entries at scale. Only 10 `finding_created` and 10 `control_assessed` entries exist for 14K+ findings and 747K+ results.
- **Impact**: Audit trail is incomplete -- an assessor would flag this immediately. "Show me the audit trail for every control status change" would return < 0.01% coverage.
- **Effort**: L (requires audit entry creation in pipeline hot path without killing performance)

### P2 - Medium

#### BUG-05: 6 framework policy directories have only 1 stub policy with 0 tests
- **Frameworks**: EU AI Act (1/0), FedRAMP (1/0), ISO 27701 (1/0), ISO 42001 (1/0), SEC Cyber (1/0)
- **Impact**: These frameworks claim OPA policy evaluation but have essentially no coverage. Pipeline OPA stage runs but evaluates nothing meaningful for these frameworks.
- **Effort**: L (each framework needs 10-30+ policies with tests)

#### BUG-06: Assertion coverage at 23.5% (489 of 2,084 controls)
- **Evidence**: `warlock assertions coverage` shows 1,595 controls without any assertion
- **Impact**: 76.5% of controls fall through to Tier 2 (AI) or remain `not_assessed`. For frameworks without AI enabled, these controls are perpetually unassessed.
- **Effort**: XL (need ~100+ more assertions to reach 50%+ coverage)

#### BUG-07: 18 database tables are completely empty in the demo
- **Tables**: `api_keys`, `assets`, `branding_configs`, `change_requests`, `compliance_obligations`, `dead_letter_queue`, `delegation_grants`, `embeddings`, `escalation_policies`, `ip_allowlist`, `policy_history`, `risk_dependencies`, `sandbox_environments`, `saved_queries`, `trust_access_requests`, `trust_documents`, `watch_subscriptions`, `workpapers`
- **Impact**: CLI commands and API routes that query these tables will show "no data" in the demo. Per CLAUDE.md Rule 8: "No data = failed demo."
- **Effort**: M (extend demo_seed.py for each table)

#### BUG-08: `warlock vendors` command doesn't accept `list` subcommand
- **Error**: `Got unexpected extra argument (list)` -- the command is `warlock vendors` (no subcommand), but it has no `invoke_without_command=True` summary
- **Impact**: Inconsistent CLI UX; most other commands use subcommands
- **Effort**: S

---

## Section 3: What's Missing (Gaps vs. Modern GRC Platforms)

### P0 - Critical Gaps

#### GAP-01: No OSCAL Assessment Plan (SAP) export
- **Current state**: The audit-package exports AR, SSP, POA&M, and component-definition but no SAP
- **Why it matters**: FedRAMP requires SAP as part of the authorization package. The `import-ap` in AR references `/api/v1/assessment-plans/latest` which doesn't exist.
- **Comparables**: Drata, Vanta don't do OSCAL at all; this is a differentiator if completed
- **Effort**: M

#### GAP-02: No evidence document management (upload, version, tag, expire)
- **Current state**: `EvidenceVault` class exists with S3/GCS/local backends, but no Evidence model in the database. `evidence gaps` correctly reports "747,704 of 747,704 controls lack uploaded evidence documents." Pipeline lineage (raw event UUIDs) is not the same as auditor-grade evidence.
- **Why it matters**: Every GRC platform (Drata, Vanta, Anecdotes, Hyperproof) has evidence lifecycle as a core feature. Without it, auditors have no artifacts to review. The `evidence attach` command exists but there's no persistent evidence catalog.
- **Effort**: L

#### GAP-03: 3 frameworks have no OSCAL catalog packages
- **Missing**: NIST CSF 2.0, EU AI Act, SEC Cyber Disclosure Rules
- **Impact**: Cannot export OSCAL artifacts for these frameworks. Breaks the "every framework has OSCAL" claim.
- **Effort**: M (create catalog JSON + profile JSON for each)

### P1 - High Gaps

#### GAP-04: No continuous evidence collection automation
- **Current state**: Pipeline collects evidence on-demand (`warlock collect`). No scheduled, automated evidence refresh.
- **Why it matters**: Modern platforms (Drata, Vanta) continuously pull evidence from integrations. Stale evidence = audit findings. The scheduler exists (`/api/v1/scheduler/start`) but evidence refresh cadence is not configurable per control.
- **Effort**: L

#### GAP-05: No evidence sufficiency scoring
- **Current state**: Evidence freshness report exists but no sufficiency analysis -- "does this evidence actually prove the control is implemented?"
- **Why it matters**: Hyperproof and Anecdotes score evidence sufficiency. Assessors reject insufficient evidence even if it's fresh. Need: relevance scoring, completeness check, mapping evidence to specific control requirements.
- **Effort**: L

#### GAP-06: No real-time compliance notifications/webhooks for external consumers
- **Current state**: Webhook model exists but no compliance-event-triggered outbound webhooks (e.g., "control AC-2 degraded from compliant to non_compliant, notify Slack/PagerDuty/ServiceNow")
- **Why it matters**: Modern GRC is event-driven. SecOps teams need real-time notification of compliance drift.
- **Effort**: M

#### GAP-07: No compliance program management (audit calendar, milestone tracking, assessor coordination)
- **Current state**: `warlock calendar` exists, audit engagements exist, but no end-to-end audit program lifecycle: schedule assessment -> assign assessors -> track milestones -> collect evidence -> review findings -> issue report -> track remediation
- **Why it matters**: ServiceNow GRC and Hyperproof differentiate on audit workflow orchestration
- **Effort**: XL

#### GAP-08: No FAIR risk quantification CLI/API integration
- **Current state**: `RiskEngine` class in `risk_engine.py` implements full FAIR Monte Carlo with loss exceedance curves, but it's not exposed via CLI commands or API endpoints in a user-friendly way. `warlock risk-review` exists as interactive workflow only.
- **Why it matters**: The FAIR engine is a major differentiator but buried in code. Need: `warlock risk quantify --scenario <id>` and `/api/v1/risk/scenarios/{id}/simulate`
- **Effort**: M

#### GAP-09: No control testing program management
- **Current state**: `warlock control-tests` commands exist (schedule, execute, gaps, history) but the demo has no test data. Control testing is foundational for SOC 2 Type II and ISO 27001 surveillance audits.
- **Why it matters**: Assessors want to see test results, not just automated checks. Manual control tests (walkthroughs, inquiries, observations) need tracking.
- **Effort**: M (seed data + workflow completion)

### P2 - Medium Gaps

#### GAP-10: No SSP narrative generation beyond OSCAL
- **Current state**: OSCAL SSP export produces machine-readable JSON. No human-readable SSP document (Word/PDF) generation with proper narrative language.
- **Why it matters**: FedRAMP requires human-readable SSP. Auditors review Word documents, not JSON. Vanta and Drata generate human-readable reports.
- **Effort**: L

#### GAP-11: No compliance score trending/historical analysis
- **Current state**: `posture_snapshots` table exists but is empty. `posture/history` API endpoint exists. No CLI command to show score over time.
- **Why it matters**: Board-level reporting requires trend lines. "We improved from 62% to 78% this quarter" is the executive conversation.
- **Effort**: M (populate snapshots in pipeline, add trend CLI)

#### GAP-12: No automated remediation playbooks
- **Current state**: Remediation steps exist as static text in assertion metadata. `warlock remediate-guided` provides interactive guidance. No automated remediation (e.g., "auto-rotate this key" or "auto-enable encryption").
- **Why it matters**: Drata and Vanta offer auto-remediation for common misconfigurations. Reduces MTTR.
- **Effort**: XL (requires safe, reversible automation with approval gates)

#### GAP-13: No customer-facing trust center / compliance portal
- **Current state**: Trust portal API exists (`/trust/*`) but no hosted trust center UI. Trust documents table is empty.
- **Why it matters**: Drata, Vanta, SafeBase all offer hosted trust centers as a product feature. Reduces security questionnaire burden.
- **Effort**: L

#### GAP-14: No SIG/CAIQ questionnaire automation
- **Current state**: Vendor questionnaire templates exist but no inbound questionnaire handling (customer sends you a SIG, system pre-fills from evidence)
- **Why it matters**: Enterprise sales teams spend 20+ hours per quarter on security questionnaires. Auto-fill from evidence is a top-requested feature.
- **Effort**: L

#### GAP-15: No data classification / DLP integration
- **Current state**: `data_silos` model exists with classification fields. `data-silos-discover` auto-discovers from findings. But no DLP tool integration (Macie, Purview, BigQuery DLP).
- **Why it matters**: Privacy frameworks (GDPR, CCPA) require knowing where PII lives. Auto-discovery from DLP tools closes this gap.
- **Effort**: M

#### GAP-16: No board reporting / executive PDF export
- **Current state**: `warlock dashboard executive` produces a terminal table. No PDF/slide generation.
- **Why it matters**: CISOs present to boards quarterly. Need exportable reports, not terminal output.
- **Effort**: M

#### GAP-17: No GRC-as-Code workflow (define controls in YAML/HCL, version in git, CI/CD for compliance)
- **Current state**: Frameworks defined in YAML, policies in Rego. But no git-native workflow where control definitions, evidence mappings, and assessment results are PR-reviewed and CI-validated.
- **Why it matters**: Engineering-first GRC teams want to manage compliance like code. Drata/Vanta are SaaS-first; this is a differentiator opportunity.
- **Effort**: L

### P3 - Nice to Have

#### GAP-18: No AI-powered control narrative generation for SSP
- **Current state**: AI reasoning assesses control status but doesn't generate SSP narrative text (the "how this control is implemented" prose that goes in an SSP).
- **Effort**: M

#### GAP-19: No compliance benchmarking (compare your posture against industry peers)
- **Current state**: No benchmark data or peer comparison capability.
- **Effort**: XL

#### GAP-20: No regulatory change feed integration (track NIST/ISO/SEC updates automatically)
- **Current state**: `RegulatoryChangeManager` exists but requires manual change creation. No integration with regulatory RSS/API feeds.
- **Effort**: M

#### GAP-21: No SBOM/supply chain risk integration
- **Current state**: No CycloneDX/SPDX ingestion. No VEX document support. Supply chain risk is a growing FedRAMP/CMMC requirement.
- **Effort**: L

#### GAP-22: No quantum readiness assessment
- **Current state**: No crypto inventory, no PQC migration tracking. NIST PQC standards are finalized.
- **Effort**: M

#### GAP-23: No SOC 2 Type II continuous monitoring period tracking
- **Current state**: SOC 2 framework exists but no concept of "observation period" where controls must be effective continuously for 3-12 months.
- **Effort**: M

---

## Summary

| Category | Count |
|----------|-------|
| Working features verified | 15 major areas |
| Bugs / broken items | 8 (1 P0, 4 P1, 3 P2) |
| Missing features | 23 (3 P0, 6 P1, 8 P2, 6 P3) |

### Top 5 Priorities

1. **BUG-01 (P0, S)**: Fix evidence gaps Rich markup crash -- quick win, blocks audit prep workflow
2. **GAP-02 (P0, L)**: Evidence document management -- fundamental GRC capability, blocks real usage
3. **BUG-02 (P1, M)**: Fix OSCAL SSP required fields -- blocks FedRAMP/OSCAL compliance claims
4. **SEC-01 (P1, L)**: Audit trail completeness -- assessors will flag 0.01% coverage immediately
5. **GAP-01 (P0, M)**: OSCAL SAP export -- completes the FedRAMP authorization package
