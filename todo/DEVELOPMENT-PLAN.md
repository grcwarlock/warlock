# Warlock Development Plan: Path to v1.0

**Created:** 2026-03-22
**Target:** First paying customers on a self-hosted deployment
**Team assumption:** 1-2 developers (solo founder + occasional contractor)
**Sprint cadence:** 2 weeks
**Backlog source:** BACKLOG.md (279 open items)

---

## What "v1.0" Means

v1.0 is the minimum product that a compliance-conscious organization would pay $8-12K/year for. It is NOT the full vision. It is the smallest thing that replaces a spreadsheet-based compliance workflow for a team preparing for SOC 2 or ISO 27001 certification.

### v1.0 must have

1. **Security that does not embarrass us.** All P0 hardening items fixed. No auth bypasses, no leaked secrets, no unbounded memory growth.
2. **A working pipeline end-to-end with real connectors.** At least 10-15 connectors that actually hit real APIs (not just demo mocks). AWS, Okta, CrowdStrike, GitHub, Jira, Slack are table stakes.
3. **Usable CLI and API with documentation.** A new user can install, configure connectors, run the pipeline, and query results without reading source code.
4. **One complete framework story.** SOC 2 Type II from end to end: collection, mapping, assessment, evidence export, POA&M tracking.
5. **Deployment that works.** Docker Compose for self-hosted. Clear setup guide. No "works on my machine" issues.
6. **Alerting.** When controls fail or drift, the system tells you. Email or Slack at minimum.
7. **Export for auditors.** OSCAL export already exists. Add PDF report generation so compliance teams can hand something to an auditor.

### v1.0 explicitly does NOT have

- Web frontend (CLI + API is the v1.0 interface; web is v1.5)
- Multi-tenancy (single-tenant self-hosted is fine for $8-12K customers)
- Data lake features beyond what already works
- AI governance / Shadow AI detection
- More than 4-5 frameworks (SOC 2, ISO 27001, NIST 800-53, HIPAA, NIST CSF)
- Risk quantification beyond what exists (FAIR Monte Carlo is already built)
- GraphQL, WebSockets, real-time dashboards
- Tier 2/3 connectors (Ping Identity, VMware, etc.)
- Privacy-specific features (consent management, cross-border tracking)
- Plugin architecture

---

## Timeline Overview

| Phase | Sprints | Calendar | Focus |
|-------|---------|----------|-------|
| Phase 1: Harden | S1-S2 | Weeks 1-4 | Security fixes, test gaps, stability |
| Phase 2: Real Connectors | S3-S4 | Weeks 5-8 | Validate 10-15 connectors against real APIs |
| Phase 3: Product Gaps | S5-S6 | Weeks 9-12 | Alerts, remediation workflow, AI output |
| Phase 4: Documentation | S7 | Weeks 13-14 | All P0 docs, deployment guide, CLI reference |
| Phase 5: SOC 2 Story | S8 | Weeks 15-16 | End-to-end SOC 2 flow, PDF reports |
| Phase 6: Beta | S9-S10 | Weeks 17-20 | Beta deployments, bug fixes, polish |
| **v1.0 GA** | | **Week 20** | |

20 weeks. 5 months. That is the honest timeline for a 1-2 person team.

---

## Phase 1: Harden (Sprints 1-2, Weeks 1-4)

The codebase has real security issues that would be career-ending if discovered by a customer's security team. Fix them before anyone sees the product.

### Sprint 1 (Weeks 1-2)

**Theme: P0 security fixes**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| H-12 | Scope AI conversation sessions to user | M | Auth bypass -- any user reads others' sessions |
| H-22 | GDPR anonymization hardcoded HMAC secret | S | Move to config, rotate on deploy |
| H-29 | Legacy SHA-256 password hashes accepted | M | Force migration to bcrypt on next login |
| H-35 | No UniqueConstraint on ControlResult/PostureSnapshot | M | Prevents duplicate results corrupting posture |
| H-36 | AuditEntry.sequence Integer vs BigInteger mismatch | S | Migration to fix column type |
| H-30 | Pipeline runs all connectors in one transaction | L | Split into per-connector transactions |

**Acceptance criteria:**
- All 6 items merged and passing QA gate
- Demo seed still produces exact expected numbers (81/0/358/5007/373852)
- No new test failures introduced

### Sprint 2 (Weeks 3-4)

**Theme: Stability and test coverage**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| H-10 | Create tests/conftest.py, unify DB setup, test 43 CLI commands | L | Foundation for all future testing |
| H-11 | Unify prompt sanitization paths | M | Security hygiene |
| H-13 | Increase backup code entropy to 64 bits | S | NIST SP 800-63B compliance |
| H-14 | Add CHECK constraints on status/enum columns | M | Data integrity |
| H-15 | MemoryCache eviction for rate limiter | S | Prevents OOM in production |
| H-23 | AI error messages leak internal details | S | Information disclosure |
| H-25 | Swallowed exceptions in connectors | M | Critical for real connector debugging |
| H-26 | NormalizerRegistry failure counter never fires | S | Observability |
| H-31 | Connection pool too small for production | S | Config change |

**Acceptance criteria:**
- CLI test coverage reaches 80%+ of commands (was 0%)
- All CHECK constraints in place via migration
- Rate limiter memory bounded
- No information leakage in error responses
- Demo seed still passes

---

## Phase 2: Real Connectors (Sprints 3-4, Weeks 5-8)

The 82 connectors today are mock implementations that produce demo data. For v1.0, at least 10-15 must work against real APIs. This is the highest-risk phase because it depends on external API access and documentation accuracy.

### Sprint 3 (Weeks 5-6)

**Theme: Connector validation framework + first 5 real connectors**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| OPS-6 | Connector vendor accuracy pass (first 5) | XL | AWS, Okta, GitHub, CrowdStrike, Jira |
| H-24 | Rate limiter ineffective with multiple workers | M | Need this before real API calls |
| OPS-7 | Schema registry for event_types | M | Validate connector output shape |

The 5 connectors chosen for Sprint 3 cover the most common enterprise stack:
- **AWS** (cloud infrastructure -- nearly universal)
- **Okta** (identity -- 17K+ customers)
- **GitHub** (code -- where the developers are)
- **CrowdStrike** (endpoint security -- market leader)
- **Jira** (project management -- issue tracking for POA&Ms)

**Acceptance criteria for each connector:**
- Connects to real API with test credentials
- Returns data matching the documented schema
- Normalizer produces valid FindingData from real responses
- Health check endpoint works
- Error handling covers rate limits, auth failures, network timeouts
- Integration test with recorded responses (VCR/cassette pattern)

### Sprint 4 (Weeks 7-8)

**Theme: Next 10 real connectors + ServiceNow**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| OPS-6 (cont.) | Connector vendor accuracy pass (next 10) | XL | See list below |
| C-1 | ServiceNow GRC connector | M | P1, enterprise buyers need this |
| DL-WIRE | Wire orchestrator to lake writers | M | Pipeline should write to lake |
| OPS-5 | nltk CVE remediation | S | Dependency vulnerability |

Next 10 connectors (prioritized by customer demand for SOC 2/ISO):
- **Entra ID** (Azure AD -- Microsoft shops)
- **GCP** (second cloud provider)
- **SentinelOne** (EDR alternative to CrowdStrike)
- **Tenable** (vulnerability management)
- **Qualys** (vulnerability management)
- **Wiz** (cloud security)
- **Slack** (communications monitoring)
- **Google Workspace** (email/docs)
- **Datadog** (monitoring)
- **Snyk** (code security)

**Acceptance criteria:**
- 15+ connectors validated against real APIs
- ServiceNow connector complete with normalizer
- Each connector has at least 1 integration test with recorded responses
- Pipeline orchestrator writes to lake when enabled
- Demo seed still passes (mock connectors unchanged)

---

## Phase 3: Product Gaps (Sprints 5-6, Weeks 9-12)

These are the features that turn "a pipeline that produces data" into "a product someone would pay for."

### Sprint 5 (Weeks 9-10)

**Theme: Alerts and AI output**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| PG-1 | Alert model + CLI + API | XL | Core model: severity, MITRE ATT&CK, finding linkage |
| PG-2 | Alert rules engine | L | Finding patterns trigger alerts |
| PG-6 | AI reasoning structured output | M | {confidence, reasoning[], evidence[]} |

**Acceptance criteria:**
- Alert model in DB with migration
- `warlock alerts list`, `warlock alerts ack`, `warlock alerts resolve` CLI commands
- API endpoints: GET/POST/PATCH /alerts
- At least 5 built-in alert rules (e.g., "control failed that was previously passing", "new critical finding", "connector health check failed")
- AI reasoning returns structured JSON, not freeform text
- Demo seed generates sample alerts
- Demo seed numbers unchanged for existing entities

### Sprint 6 (Weeks 11-12)

**Theme: Remediation workflow and pipeline status**

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| PG-7 | Remediation workflow API (5-stage state machine) | L | Open > Assigned > In Progress > Verification > Closed |
| PG-8 | Real-time pipeline status API | M | GET /pipeline/status |
| PG-9 | Per-connector collection status API | M | GET /connectors/{id}/status |
| PG-11 | Hash chain verification endpoint | S | GET /pipeline/verify-chain |
| PG-22 | Slack/Teams notification integration | M | Alert delivery channel |

**Acceptance criteria:**
- Remediation workflow with state machine validation (no invalid transitions)
- Pipeline status shows current stage, progress, errors
- Per-connector status shows last run, success/failure, event count
- Hash chain verification returns pass/fail with first broken link
- Slack webhook delivers alert notifications
- All new endpoints have ABAC enforcement
- Demo seed exercises remediation workflow

---

## Phase 4: Documentation (Sprint 7, Weeks 13-14)

No one will adopt a product they cannot figure out how to use. This sprint is documentation-only. No code changes except typo fixes.

### Sprint 7 (Weeks 13-14)

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| DOC-4 | OpenAPI schema export | S | FastAPI generates this -- just verify and publish |
| DOC-1 | API_REFERENCE.md (153 routes) | L | Generate from OpenAPI, add examples |
| DOC-8 | CLI_REFERENCE.md (42+ commands) | M | Generate from Click help, add examples |
| DOC-2 | API_AUTH_GUIDE.md | M | JWT flow, API key creation, RBAC/ABAC |
| DOC-5 | DEPLOYMENT_GUIDE.md | L | Docker Compose, env vars, PostgreSQL, OPA |
| DOC-6 | DOCKER_SETUP.md | M | Step-by-step Docker deployment |
| DOC-9 | DEVELOPER_SETUP.md | M | Local dev environment |
| DOC-3 | API_ERRORS.md | M | Error code reference |
| DOC-7 | SECURITY_HARDENING.md | L | Production security checklist |
| DOC-10 | CONTRIBUTING.md update | S | |
| DOC-11 | PR template | S | |
| DOC-12 | README accuracy fixes | S | |

**Acceptance criteria:**
- All 12 P0 docs written and reviewed
- OpenAPI spec exported and accessible at /docs in non-production
- README reflects current state (connector count, test count, framework count)
- A new developer can go from `git clone` to running demo in under 15 minutes using only the docs
- A new user can configure a real connector and run the pipeline using only the docs
- QA gate doc accuracy check passes

---

## Phase 5: SOC 2 End-to-End (Sprint 8, Weeks 15-16)

The first customer story: "I am preparing for SOC 2 Type II and I want to automate evidence collection and assessment."

### Sprint 8 (Weeks 15-16)

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| PG-18 | PDF report generation | L | WeasyPrint or ReportLab |
| PG-19 | Executive summary template | M | One-page posture overview |
| F-27 | SOC 2 points of focus (200+) | L | Deeper SOC 2 coverage |
| F-28 | Attestation workflow (SOC 2/ISO) | L | Sign-off chain for audit readiness |
| OPS-1 | Wire FedRAMP/HIPAA/CMMC/GDPR checks to event_types | M | Needed for framework completeness |

**Acceptance criteria:**
- PDF report generates for any framework with findings, results, and posture score
- Executive summary fits on one page with posture score, top risks, trend
- SOC 2 coverage includes Trust Services Criteria points of focus
- Attestation workflow supports: prepare > review > attest > archive
- A compliance manager can demonstrate the full SOC 2 flow:
  1. Configure connectors (Okta, AWS, GitHub, CrowdStrike)
  2. Run pipeline
  3. Review control results filtered to SOC 2
  4. Create POA&Ms for failed controls
  5. Export PDF report
  6. Export OSCAL assessment results
  7. Generate audit evidence binder

---

## Phase 6: Beta (Sprints 9-10, Weeks 17-20)

Deploy to 2-3 beta customers. Fix what breaks. Polish what confuses.

### Sprint 9 (Weeks 17-18)

**Theme: Beta deployment and first feedback**

- Deploy to beta customer 1 (target: a startup preparing for SOC 2)
- Daily check-ins for first week
- Track: setup time, first-pipeline-run time, questions asked, errors hit
- Fix blocking issues immediately (reserve 50% of sprint capacity for reactive work)
- Begin writing 3-4 P1 framework guides (DOC-13 through DOC-18) as customers request them

### Sprint 10 (Weeks 19-20)

**Theme: Polish and GA prep**

- Deploy to beta customers 2-3
- Fix all blocking and high-severity issues from beta feedback
- Performance testing: verify pipeline runs in reasonable time with real data volumes
- Write changelog, version tag, release notes
- Set up license key / entitlement system (can be simple -- signed JWT with expiry)
- Prepare pricing page and sales materials

**v1.0 GA acceptance criteria:**
- 3 beta customers have successfully run the pipeline against real infrastructure
- Zero P0 bugs open
- All P0 documentation complete
- Docker Compose deployment works on a fresh Ubuntu 22.04 VM in under 30 minutes
- Pipeline completes in under 10 minutes for 15 connectors
- PDF report generates without errors
- OSCAL export validates against OSCAL schema

---

## What Comes After v1.0

These items are explicitly deferred. They are important but not required for first revenue.

### v1.1 (Weeks 21-26) -- Expand frameworks and connectors

- FW-1: CIS Controls v8
- FW-2: DORA (EU financial, mandatory)
- FW-3: NIS2 (EU network security)
- FW-4: CCPA/CPRA
- 10 more validated connectors (Tier 2 list)
- H-16: Async migration (needed before 50+ concurrent users)

### v1.5 (Weeks 27-36) -- Web frontend

- PG-23 through PG-28: Web frontend (Next.js + React)
- F-18: Multi-tenancy (needed for Professional tier)
- F-19: WebSocket real-time dashboard
- PG-10: WebSocket for live pipeline progress

### v2.0 -- Platform

- F-20: Plugin architecture for connectors
- F-21: Compliance-as-code SDK
- F-13: Natural language compliance queries
- F-16: Remediation copilot
- Tier 2/3 connectors based on customer demand

---

## Risks and Mitigations

### Risk 1: Real connector validation takes longer than estimated

**Likelihood:** High
**Impact:** Pushes v1.0 by 4-8 weeks
**Mitigation:** Start with the 5 most critical connectors. If a connector's API is poorly documented or unstable, drop it from v1.0 and substitute another. The pipeline works fine with 10 real connectors instead of 15.

### Risk 2: Solo developer bottleneck

**Likelihood:** High (if solo)
**Impact:** Everything takes 2x longer
**Mitigation:** Prioritize ruthlessly. The documentation sprint (Phase 4) can be partially outsourced to a technical writer. Connector validation (Phase 2) is parallelizable -- a contractor can validate connectors independently if given test credentials and acceptance criteria.

### Risk 3: Beta customers find architectural issues

**Likelihood:** Medium
**Impact:** Requires rearchitecture, delays GA by weeks
**Mitigation:** Phase 1 hardening addresses known architectural issues (single transaction, connection pool, rate limiter). The demo seed is a surprisingly good stress test. Run it 10x sequentially before beta to catch resource leaks.

### Risk 4: No beta customers available

**Likelihood:** Medium
**Impact:** Ship without real-world validation
**Mitigation:** Start outreach in Sprint 3 (Week 5). Target: compliance consultants who advise startups on SOC 2. Offer free access during beta in exchange for feedback. Compliance consultants see dozens of companies per year and can provide representative use cases.

### Risk 5: Competitor ships similar depth-first approach

**Likelihood:** Low (Drata/Vanta are breadth-first)
**Impact:** Reduces differentiation window
**Mitigation:** Warlock's moat is technical depth: OPA policies, hash-chained audit trail, OSCAL, self-hostable. These are hard to replicate. Ship v1.0 and let the product speak. Do not rush features to "beat" competitors.

### Risk 6: AI reasoning produces unreliable results for customers

**Likelihood:** Medium
**Impact:** Loss of trust, compliance teams revert to manual
**Mitigation:** PG-6 (structured AI output) is in Phase 3 for this reason. The confidence floor (0.7) rejects low-confidence assessments. v1.0 messaging should position AI as "augmentation" not "automation." Deterministic assertions handle the majority of controls.

---

## Team Sizing

### Solo developer (realistic minimum)

- Timeline: 20 weeks as written
- Biggest constraint: connector validation requires API access and domain expertise
- Can ship v1.0 but beta support will be consuming

### 2-person team (recommended)

- Developer 1: Backend (hardening, pipeline, models, API)
- Developer 2: Connectors + documentation
- Timeline compresses to ~14-16 weeks because connector validation and docs parallelize
- This is the sweet spot for getting to revenue

### 3-person team (ideal)

- Developer 1: Backend core
- Developer 2: Connectors and integrations
- Developer 3: Documentation, testing, beta support
- Timeline compresses to ~12 weeks
- Diminishing returns beyond 3 people at this stage -- the codebase is not large enough to support more parallel work without constant merge conflicts

### Contractor opportunities (can be done independently)

- Technical writer: P0 documentation (Sprint 7)
- Connector developer: Validate connectors against real APIs (Sprints 3-4)
- Security reviewer: Penetration test before beta (Sprint 8)

---

## Sprint-by-Sprint Checklist

Use this as a tracking sheet. Check items off as sprints complete.

### Sprint 1 (Weeks 1-2) -- P0 Security ✓ COMPLETE (2026-03-23)
- [x] H-12: AI session scoping
- [x] H-22: GDPR HMAC secret
- [x] H-29: Password hash migration
- [x] H-35: UniqueConstraint on ControlResult/PostureSnapshot
- [x] H-36: AuditEntry sequence type
- [x] H-30: Per-connector transactions
- [x] Demo seed passes with exact expected numbers
- [x] QA gate passes

### Sprint 2 (Weeks 3-4) -- Stability
- [ ] H-10: Test infrastructure + CLI coverage
- [ ] H-11: Prompt sanitization
- [ ] H-13: Backup code entropy
- [ ] H-14: CHECK constraints
- [ ] H-15: MemoryCache eviction
- [ ] H-23: AI error message leakage
- [ ] H-25: Connector exception handling
- [ ] H-26: Normalizer failure counter
- [ ] H-31: Connection pool sizing
- [ ] Demo seed passes
- [ ] QA gate passes

### Sprint 3 (Weeks 5-6) -- First 5 Real Connectors
- [ ] AWS connector validated against real API
- [ ] Okta connector validated
- [ ] GitHub connector validated
- [ ] CrowdStrike connector validated
- [ ] Jira connector validated
- [ ] OPS-7: Schema registry for event_types
- [ ] H-24: Rate limiter for multiple workers
- [ ] Integration tests with recorded responses for each
- [ ] Demo seed passes

### Sprint 4 (Weeks 7-8) -- Next 10 Connectors + ServiceNow
- [ ] C-1: ServiceNow GRC connector
- [ ] 10 more connectors validated (Entra ID, GCP, SentinelOne, Tenable, Qualys, Wiz, Slack, Google Workspace, Datadog, Snyk)
- [x] DL-WIRE: Pipeline writes to lake
- [ ] OPS-5: nltk CVE fix
- [ ] 15+ total connectors working against real APIs
- [ ] Demo seed passes

### Sprint 5 (Weeks 9-10) -- Alerts + AI
- [ ] PG-1: Alert model + CLI + API
- [ ] PG-2: Alert rules engine (5+ built-in rules)
- [ ] PG-6: AI structured output
- [ ] Demo seed generates alerts
- [ ] Demo seed passes

### Sprint 6 (Weeks 11-12) -- Remediation + Status
- [ ] PG-7: Remediation workflow (5-stage state machine)
- [ ] PG-8: Pipeline status API
- [ ] PG-9: Per-connector status API
- [ ] PG-11: Hash chain verification endpoint
- [ ] PG-22: Slack notification integration
- [ ] All new endpoints have ABAC enforcement
- [ ] Demo seed passes

### Sprint 7 (Weeks 13-14) -- Documentation
- [ ] DOC-4: OpenAPI export
- [ ] DOC-1: API reference
- [ ] DOC-8: CLI reference
- [ ] DOC-2: Auth guide
- [ ] DOC-5: Deployment guide
- [ ] DOC-6: Docker setup
- [ ] DOC-9: Developer setup
- [ ] DOC-3: Error reference
- [ ] DOC-7: Security hardening
- [ ] DOC-10: CONTRIBUTING.md
- [ ] DOC-11: PR template
- [ ] DOC-12: README accuracy
- [ ] New user test: clone to running demo in <15 minutes

### Sprint 8 (Weeks 15-16) -- SOC 2 Story
- [ ] PG-18: PDF report generation
- [ ] PG-19: Executive summary template
- [ ] F-27: SOC 2 points of focus
- [ ] F-28: Attestation workflow
- [ ] OPS-1: Framework event_type wiring
- [ ] End-to-end SOC 2 demo walkthrough documented
- [ ] Demo seed passes

### Sprint 9 (Weeks 17-18) -- Beta 1
- [ ] Beta customer 1 deployed
- [ ] Daily check-ins scheduled
- [ ] Blocking issues tracked and fixed
- [ ] Setup time recorded (<30 min target)
- [ ] First pipeline run time recorded (<10 min target)

### Sprint 10 (Weeks 19-20) -- Beta 2-3 + GA
- [ ] Beta customers 2-3 deployed
- [ ] All blocking bugs from beta fixed
- [ ] Performance validated with real data
- [ ] License/entitlement system working
- [ ] Changelog and release notes written
- [ ] v1.0 tagged and released

---

## Items Explicitly Not in v1.0 (229 backlog items)

For clarity, here is what is cut and why.

| Category | Cut items | Reason |
|----------|-----------|--------|
| Connectors Tier 2-3 (C-2 through C-66) | 65 items | Demand-driven; add when customers ask |
| Frameworks (FW-1 through FW-10) | 10 items | v1.0 ships with existing 14; new ones in v1.1 |
| Web frontend (PG-23 through PG-29) | 7 items | CLI+API is sufficient for v1.0 technical buyers |
| P2 Features (F-1 through F-58) | 53 items | Differentiation, not table stakes |
| P3 Features (F-59 through F-76) | 18 items | Future |
| Hardening backlog (H-16 through H-21) | 6 items | Quality improvements, not blocking |
| Hardening untriaged lower (H-27, H-28, H-32, H-33, H-34) | 5 items | H-34 (test gaps) is large; address incrementally |
| Data Lake remaining (DL-3, DL-5, DL-6, DL-CROSS) | 0 items (all complete) | All implemented — REST catalog, durable backends, repo migration, crosswalk confidence |
| Demo seed enhancements (PG-14 through PG-17) | 4 items | Nice polish, not required |
| P1 Documentation (DOC-13 through DOC-37) | 25 items | Write as customers request specific guides |
| P2 Documentation (DOC-38 through DOC-57) | 20 items | Polish |
| Product gaps deferred (PG-3, PG-4, PG-5, PG-10, PG-12, PG-13, PG-20, PG-21) | 8 items | Not required for SOC 2 story |
| Operational deferred (OPS-2, OPS-3, OPS-4, OPS-8, OPS-9) | 5 items | Nice-to-have |

**Total in v1.0: ~50 items. Total deferred: ~229 items.**

The v1.0 scope is 18% of the total backlog. That is correct. Shipping 18% of the backlog that covers 90% of the value for the first customer segment is the goal.

---

## Decision Log

Decisions made in this plan that may need revisiting.

| Decision | Rationale | Revisit when |
|----------|-----------|--------------|
| No web frontend in v1.0 | Target buyers are technical; CLI+API is sufficient. Saves 6+ weeks. | First customer says "I need a dashboard" |
| SOC 2 as first framework story | Most common framework for startups/SaaS. Largest addressable market at $8-12K. | Enterprise buyer wants FedRAMP first |
| 15 real connectors, not 82 | Validating 82 connectors against real APIs would take 6 months alone | Customer needs a specific connector |
| Docker Compose only, no k8s | Self-hosted simplicity. k8s adds ops burden for small teams. | Customer requires k8s deployment |
| Skip multi-tenancy | Single-tenant is fine for Starter tier. Multi-tenancy is a v1.5 requirement for Professional. | Second customer wants shared instance |
| WeasyPrint for PDF (not ReportLab) | Better CSS support, more maintainable templates | Performance issues at scale |
| Slack notifications first (not email) | Lower effort, higher engagement in technical teams | Customer requires email |

---

## How to Use This Plan

1. **Each sprint starts** by reviewing the sprint checklist above and pulling items into active work.
2. **Each sprint ends** with: QA gate pass, demo seed pass, brief retro note on what took longer than expected.
3. **Scope changes** happen at sprint boundaries, not mid-sprint. If something is taking longer, finish it next sprint -- do not add scope to compensate.
4. **Customer feedback** overrides this plan. If a beta customer needs HIPAA instead of SOC 2, pivot. The plan is a starting point, not a contract.
5. **Track actual vs. estimated** effort for each item. After 4 sprints, you will have real velocity data and can reforecast the timeline.
