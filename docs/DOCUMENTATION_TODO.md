# Documentation Enhancement — Actionable Checklist

**Status:** Not started
**Target Completion:** 6 weeks (P0: 3 weeks, P1: 2 weeks, P2: 1 week)
**Owner:** [TBD]

---

## Priority 0: Blocking Adoption (3 Weeks, Start Immediately)

These 6 documents unblock API development, deployment, and contribution. Can be parallelized.

### API Documentation (Week 1)

- [ ] **API_REFERENCE.md** (3 days)
  - [ ] All 100+ endpoints with descriptions
  - [ ] Request payloads with examples
  - [ ] Response schemas
  - [ ] Error codes and HTTP status
  - [ ] Sample curl commands
  - [ ] Cross-link to framework guides
  - Location: `/docs/api/API_REFERENCE.md`

- [ ] **API_AUTH_GUIDE.md** (1 day)
  - [ ] JWT authentication flow
  - [ ] API key generation and scoping
  - [ ] RBAC roles (admin, auditor, owner, viewer)
  - [ ] ABAC filtering examples (allowed_frameworks, allowed_sources)
  - [ ] Token expiration and refresh
  - [ ] Account lockout policy
  - Location: `/docs/api/API_AUTH_GUIDE.md`

- [ ] **API_ERRORS.md** (1 day)
  - [ ] Complete error code reference
  - [ ] HTTP status code mapping
  - [ ] Error response format
  - [ ] Retry strategy
  - [ ] Common mistakes
  - Location: `/docs/api/API_ERRORS.md`

- [ ] **OpenAPI Schema Export** (1 day)
  - [ ] Export `/openapi.json` from running server
  - [ ] Save to `docs/openapi.json`
  - [ ] Add to `.gitignore` or commit?
  - [ ] Add reference to README pointing to Swagger UI
  - [ ] Consider: Postman collection generation
  - Location: `/docs/openapi.json`

### Deployment & Operations (Week 1)

- [ ] **DEPLOYMENT_GUIDE.md** (3 days)
  - [ ] AWS deployment (Lambda/ECS/RDS/API Gateway)
  - [ ] Azure deployment (App Service/Azure DB)
  - [ ] GCP deployment (Cloud Run/Cloud SQL)
  - [ ] Docker image building and pushing
  - [ ] Environment variables configuration
  - [ ] Database migration (alembic upgrade head)
  - [ ] Verification steps
  - Location: `/docs/deployment/DEPLOYMENT_GUIDE.md`

- [ ] **DOCKER_SETUP.md** (1 day)
  - [ ] How to build Docker image
  - [ ] Image tagging strategy
  - [ ] Docker Compose for local dev (already exists, just reference it)
  - [ ] Container registry (Docker Hub, ECR, GCR, ACR)
  - [ ] Multi-stage build explanation
  - Location: `/docs/deployment/DOCKER_SETUP.md`

- [ ] **SECURITY_HARDENING.md** (2 days)
  - [ ] TLS/HTTPS setup
  - [ ] WAF (AWS WAF, Azure WAF)
  - [ ] Secrets rotation procedure
  - [ ] JWT secret generation
  - [ ] OPA policy configuration
  - [ ] Audit logging enablement
  - [ ] Security headers configuration
  - [ ] Database encryption at rest
  - [ ] Network isolation (VPC, security groups)
  - [ ] Checklist for audit readiness
  - Location: `/docs/security/SECURITY_HARDENING.md`

- [ ] Update **docs/operations/backup-and-dr.md** (1 day)
  - [ ] Expand from 57 to 200+ lines
  - [ ] Add recovery testing procedure
  - [ ] Add cross-region replication
  - [ ] Add archive strategy for compliance exports
  - [ ] Add example RDS/Cloud SQL configurations

### CLI & Developer Onboarding (Week 1-2)

- [ ] **CLI_REFERENCE.md** (2 days)
  - [ ] All 34 commands with descriptions
  - [ ] Syntax for each command
  - [ ] Flags and options
  - [ ] Real usage examples
  - [ ] Sample output
  - [ ] Group by category (Pipeline, Compliance, Remediation, etc.)
  - [ ] Common errors and solutions
  - Location: `/docs/cli/CLI_REFERENCE.md`

- [ ] **DEVELOPER_SETUP.md** (1 day)
  - [ ] System requirements (Python 3.12+, PostgreSQL, Redis)
  - [ ] Clone and virtualenv setup
  - [ ] Install dependencies (pip install -e ".[dev,ai]")
  - [ ] Database setup (SQLite for dev, PostgreSQL for testing)
  - [ ] Environment variables (.env)
  - [ ] Run tests (pytest)
  - [ ] Run demo (./scripts/demo.sh)
  - [ ] IDE setup (VSCode, PyCharm)
  - Location: `/docs/developer/DEVELOPER_SETUP.md`

- [ ] **CONTRIBUTING.md** (1 day)
  - [ ] Code of Conduct
  - [ ] How to contribute (issues, code, docs)
  - [ ] Development workflow (branching, commits, PRs)
  - [ ] PR checklist
  - [ ] Testing requirements
  - [ ] Documentation requirements
  - [ ] Code style (ruff, type hints)
  - [ ] Getting help
  - Location: `/CONTRIBUTING.md`

- [ ] **.github/pull_request_template.md** (0.5 days)
  - [ ] Description section
  - [ ] Type of change checkboxes
  - [ ] Related issue link
  - [ ] Testing checklist
  - [ ] Documentation checklist
  - Location: `/.github/pull_request_template.md`

### Accuracy Fixes (Immediate)

- [ ] **README.md line 8:** "41 normalizers" → "40 normalizers" (1 min)
- [ ] **DEMO.md line 17:** "616 Rego policies" → verify actual count (5 min)
  - Run: `find policies/ -name "*.rego" | wc -l`
- [ ] **CLAUDE.md line 77:** Verify "190 tests" (5 min)
  - Run: `pytest --collect-only -q 2>&1 | tail -1`
- [ ] **README.md:** Update any stale counts (10 min)
- [ ] **Search README/DEMO for "TBD"** — mark for author (5 min)

---

## Priority 1: High-Value Enablers (2 Weeks, After P0)

### Framework Implementation Guides (Week 3)

- [ ] **FRAMEWORKS_GUIDE.md** (1 day)
  - [ ] Overview of all 10 frameworks
  - [ ] Controls count per framework
  - [ ] Which connectors serve each framework
  - [ ] Cross-reference table (control ID → frameworks)
  - Location: `/docs/frameworks/FRAMEWORKS_GUIDE.md`

- [ ] **NIST_800_53_IMPLEMENTATION.md** (3 days)
  - [ ] NIST 800-53 Rev 5 overview
  - [ ] Control families (CA, AC, AT, AU, etc.)
  - [ ] Low/Moderate/High baselines
  - [ ] Enhancement strategy
  - [ ] Which connectors serve which controls
  - [ ] SOC 2 mapping (controls overlap)
  - [ ] Audit checklist
  - [ ] Common exceptions for startups
  - Location: `/docs/frameworks/NIST_800_53_IMPLEMENTATION.md`

- [ ] **SOC2_TYPE_II_ROADMAP.md** (2 days)
  - [ ] SOC 2 Type I vs. Type II
  - [ ] Trust Service Criteria (CC, A, C, PI, P)
  - [ ] Evidence collection strategy
  - [ ] Testing procedures per TSC
  - [ ] Report generation from Warlock
  - [ ] Timeline for Type II readiness
  - [ ] Common findings and how to resolve
  - Location: `/docs/frameworks/SOC2_TYPE_II_ROADMAP.md`

- [ ] **ISO_27001_IMPLEMENTATION.md** (2 days)
  - [ ] Annex A controls (93)
  - [ ] Audit evidence checklist
  - [ ] ISMS implementation roadmap
  - [ ] SoA (Statement of Applicability)
  - [ ] Which controls are manual vs. automated
  - [ ] Gap analysis template
  - Location: `/docs/frameworks/ISO_27001_IMPLEMENTATION.md`

- [ ] **HIPAA_COMPLIANCE_ROADMAP.md** (1 day)
  - [ ] Security Rule requirements (64 controls)
  - [ ] HIPAA-specific Warlock configuration
  - [ ] Breach notification logging
  - [ ] HIPAA audit checklist
  - Location: `/docs/frameworks/HIPAA_COMPLIANCE_ROADMAP.md`

- [ ] **CMMC_L2_IMPLEMENTATION.md** (1 day)
  - [ ] CMMC Level 2 overview
  - [ ] Maturity roadmap (Initial to Managed)
  - [ ] Practice implementation
  - [ ] Assessment preparation
  - Location: `/docs/frameworks/CMMC_L2_IMPLEMENTATION.md`

### Connector Integration Guides (Week 4)

- [ ] **CONNECTORS_GUIDE.md** (1 day)
  - [ ] Index of all 40 connectors
  - [ ] Quick start per connector category
  - [ ] Troubleshooting checklist
  - [ ] Data freshness expectations
  - Location: `/docs/connectors/CONNECTORS_GUIDE.md`

- [ ] **AWS_CONNECTOR_GUIDE.md** (1 day)
  - [ ] AWS authentication (IAM role, access key)
  - [ ] Supported regions
  - [ ] Required IAM permissions (list/matrix)
  - [ ] Assumed role configuration
  - [ ] Data collection scope
  - [ ] Common issues
  - [ ] Cost implications
  - Location: `/docs/connectors/AWS_CONNECTOR_GUIDE.md`

- [ ] **OKTA_CONNECTOR_GUIDE.md** (0.5 days)
  - [ ] Okta domain setup
  - [ ] API token generation (admin console)
  - [ ] Required Okta permissions
  - [ ] Data collection scope (users, groups, apps)
  - [ ] MFA handling
  - [ ] Sync frequency
  - Location: `/docs/connectors/OKTA_CONNECTOR_GUIDE.md`

- [ ] **GCP_CONNECTOR_GUIDE.md** (1 day)
  - [ ] GCP project setup
  - [ ] Service account creation
  - [ ] Required APIs to enable
  - [ ] IAM roles needed
  - [ ] Supported regions
  - [ ] Cross-project access
  - [ ] Organization vs. Project scope
  - Location: `/docs/connectors/GCP_CONNECTOR_GUIDE.md`

- [ ] **Connector Template** (0.5 days)
  - [ ] Create template: `CONNECTOR_TEMPLATE.md`
  - [ ] Sections: Auth, Setup, Configuration, Permissions, Troubleshooting
  - [ ] Use for remaining 36 connectors
  - Location: `/docs/connectors/CONNECTOR_TEMPLATE.md`

- [ ] **Per-Connector Guides** (6 days, can parallelize)
  - [ ] Azure, OCI, IBM Cloud, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare (Cloud)
  - [ ] CrowdStrike, Defender, SentinelOne (EDR)
  - [ ] Entra ID, CyberArk, SailPoint (IAM)
  - [ ] Tenable, Qualys, Wiz (Scanners)
  - [ ] Prisma Cloud (CSPM)
  - [ ] Sentinel, Splunk, Elastic (SIEM)
  - [ ] Workday, ServiceNow, KnowBe4 (Enterprise)
  - [ ] Others...
  - Location: `/docs/connectors/[CONNECTOR]_GUIDE.md`

### Operations & Runbooks (Week 3-4)

- [ ] **MONITORING_AND_ALERTING.md** (2 days)
  - [ ] Prometheus metrics exposed by Warlock
  - [ ] Grafana dashboard examples
  - [ ] CloudWatch alarm setup (AWS)
  - [ ] Azure Monitor setup
  - [ ] GCP Cloud Monitoring setup
  - [ ] Alert routing (Slack, PagerDuty, email)
  - [ ] Key metrics to monitor (pipeline latency, findings count, control results)
  - [ ] SLA/SLO definition
  - Location: `/docs/operations/MONITORING_AND_ALERTING.md`

- [ ] **RUNBOOK_DATABASE_FAILURE.md** (1 day)
  - [ ] Identify failure symptoms
  - [ ] Recovery from backup
  - [ ] Point-in-time recovery procedure
  - [ ] Data integrity verification
  - [ ] Post-recovery validation
  - [ ] Communication template
  - Location: `/docs/operations/RUNBOOK_DATABASE_FAILURE.md`

- [ ] **RUNBOOK_PIPELINE_STUCK.md** (1 day)
  - [ ] Identify stuck collection
  - [ ] Queue inspection (Redis/Kafka/SQS)
  - [ ] Connector health checks
  - [ ] Manual retry procedure
  - [ ] Log analysis
  - Location: `/docs/operations/RUNBOOK_PIPELINE_STUCK.md`

- [ ] **RUNBOOK_AUTH_OUTAGE.md** (1 day)
  - [ ] Users locked out due to failed auth
  - [ ] JWT secret rotation
  - [ ] API key revocation
  - [ ] Session invalidation
  - [ ] Restored access verification
  - Location: `/docs/operations/RUNBOOK_AUTH_OUTAGE.md`

- [ ] **RUNBOOK_AUDIT_TRAIL_INTEGRITY.md** (1 day)
  - [ ] Verify hash chain integrity
  - [ ] Detect tampering
  - [ ] Recovery from corruption
  - [ ] Audit trail export for forensics
  - Location: `/docs/operations/RUNBOOK_AUDIT_TRAIL_INTEGRITY.md`

### Testing & Development (Week 4)

- [ ] **TEST_STRATEGY.md** (1 day)
  - [ ] Test structure (unit, integration, demo seed)
  - [ ] Test files location and naming
  - [ ] Writing a new test
  - [ ] Running tests locally (pytest)
  - [ ] Coverage expectations (should be 80%+)
  - [ ] CI test failures and how to fix
  - [ ] Demo seed test (acceptance test)
  - Location: `/docs/developer/TEST_STRATEGY.md`

- [ ] **CODEBASE_STRUCTURE.md** (1 day)
  - [ ] Module-by-module walkthrough
  - [ ] Key classes and responsibilities
  - [ ] Data flow (raw event → finding → control result)
  - [ ] Extension points (new connector, new normalizer, new assertion)
  - [ ] Dependency map
  - [ ] Common patterns (repository pattern, event bus, etc.)
  - Location: `/docs/developer/CODEBASE_STRUCTURE.md`

- [ ] **DEVELOPMENT_WORKFLOW.md** (0.5 days)
  - [ ] Feature branch naming (feature/..., fix/..., docs/...)
  - [ ] Commit message format
  - [ ] Local testing checklist before pushing
  - [ ] PR review expectations
  - [ ] How to handle CI failures
  - [ ] Debugging tips
  - Location: `/docs/developer/DEVELOPMENT_WORKFLOW.md`

---

## Priority 2: Polish & Completeness (1 Week, After P0+P1)

### Release & Change Management (Week 5-6)

- [ ] **CHANGELOG.md** (1 day)
  - [ ] Keep a Changelog format
  - [ ] v1 → v2 migration summary
  - [ ] Current v2.0.0a1 release notes
  - [ ] Link to GitHub releases
  - Location: `/CHANGELOG.md`

- [ ] **RELEASE_PROCESS.md** (1 day)
  - [ ] Semantic versioning strategy
  - [ ] Pre-release checklist
  - [ ] Release branch creation
  - [ ] Tag naming and Docker image tagging
  - [ ] PyPI publishing (if applicable)
  - [ ] Announcement channels (GitHub releases, email, Slack)
  - [ ] Rollback procedure
  - Location: `/docs/RELEASE_PROCESS.md`

- [ ] **MIGRATION_GUIDES.md** (0.5 days)
  - [ ] v1 → v2 breaking changes
  - [ ] Database schema migration path
  - [ ] API endpoint changes
  - [ ] Configuration file migration
  - Location: `/docs/MIGRATION_GUIDES.md`

### Architecture & Design

- [ ] **ARCHITECTURE_DECISIONS.md** (1 day)
  - [ ] 6 ADRs (see below)
  - [ ] Format: Context, Decision, Consequences, Alternatives
  - Location: `/docs/architecture/ARCHITECTURE_DECISIONS.md`

- [ ] **ADR-001: Pipeline Architecture** (0.25 days)
  - [ ] Why 4-stage pipeline?
  - [ ] Why immutable data at each stage?
  - [ ] Trade-offs considered
  - Location: `/docs/architecture/ADR-001-pipeline-architecture.md`

- [ ] **ADR-002: Hash-Chained Audit Trail** (0.25 days)
  - [ ] Why SHA-256 integrity hashes?
  - [ ] Why chain every stage?
  - [ ] Compliance implications
  - Location: `/docs/architecture/ADR-002-hash-chained-audit.md`

- [ ] **ADR-003: Assessment Tiers** (0.25 days)
  - [ ] Why Tier 1-4?
  - [ ] When to use AI reasoning?
  - [ ] Confidence scoring
  - Location: `/docs/architecture/ADR-003-assessment-tiers.md`

- [ ] **ADR-004: Framework Representation** (0.25 days)
  - [ ] Why YAML for framework definitions?
  - [ ] Crosswalk representation
  - [ ] Control inheritance
  - Location: `/docs/architecture/ADR-004-framework-yaml.md`

- [ ] **ADR-005: OPA Policy Evaluation** (0.25 days)
  - [ ] Why OPA?
  - [ ] Why optional (not mandatory)?
  - [ ] Fail-closed vs. fail-open
  - Location: `/docs/architecture/ADR-005-opa-policies.md`

- [ ] **ADR-006: Multi-Tenancy Model** (0.25 days)
  - [ ] System profiles as authorization boundaries
  - [ ] ABAC scoping
  - [ ] Data isolation
  - Location: `/docs/architecture/ADR-006-multitenancy.md`

### Code Style & Quality

- [ ] **CODE_STYLE_GUIDE.md** (0.5 days)
  - [ ] Python style (follow ruff linter)
  - [ ] Type hints expectations
  - [ ] Docstring format (Google style)
  - [ ] Naming conventions (snake_case, CONSTANT_NAMES)
  - [ ] Import organization
  - [ ] Line length (100 chars)
  - Location: `/docs/developer/CODE_STYLE_GUIDE.md`

- [ ] **FIRST_CONTRIBUTION.md** (0.5 days)
  - [ ] How to find a good starter issue
  - [ ] Step-by-step first PR walkthrough
  - [ ] Testing your changes
  - [ ] Creating a PR
  - [ ] Responding to review feedback
  - Location: `/docs/developer/FIRST_CONTRIBUTION.md`

### Security & Compliance

- [ ] **SECURITY_ARCHITECTURE.md** (1 day)
  - [ ] Threat model (actors, threats, mitigations)
  - [ ] Defense-in-depth diagram
  - [ ] OWASP Top 10 mapping (how Warlock addresses each)
  - [ ] Authentication & authorization design
  - [ ] Encryption strategy (at rest, in transit)
  - Location: `/docs/security/SECURITY_ARCHITECTURE.md`

- [ ] **COMPLIANCE_DESIGN.md** (1 day)
  - [ ] How Warlock itself achieves SOC 2
  - [ ] How Warlock achieves ISO 27001
  - [ ] How Warlock achieves HIPAA
  - [ ] Evidence collection for auditors
  - Location: `/docs/security/COMPLIANCE_DESIGN.md`

---

## Timeline Summary

| Week | Task | Effort | P0/P1/P2 |
|------|------|--------|----------|
| 1 | API + Deployment + CLI (parallel) | 5 days | P0 |
| 1-2 | Developer + Contributing (parallel) | 3 days | P0 |
| Immed | Accuracy fixes | 0.5 days | P0 |
| 3 | Framework guides (parallel) | 7 days | P1 |
| 4 | Connector guides (parallel) | 7 days | P1 |
| 3-4 | Operations runbooks | 5 days | P1 |
| 4 | Development strategy docs | 2.5 days | P1 |
| 5 | Release management | 2.5 days | P2 |
| 5-6 | Architecture & style | 4 days | P2 |
| 5-6 | Security whitepaper | 2 days | P2 |
| **TOTAL** | **58 documents** | **~39 days (6 weeks if parallelized)** | **Mixed** |

**With parallel teams:**
- **P0 (blocking adoption):** 2 weeks
- **P0+P1 (ready for enterprises):** 4 weeks
- **P0+P1+P2 (complete):** 6 weeks

---

## Tracking

| Document | Status | Owner | Due Date | Notes |
|----------|--------|-------|----------|-------|
| API_REFERENCE.md | ⬜ Not started | | | Blocks API clients |
| API_AUTH_GUIDE.md | ⬜ Not started | | | |
| API_ERRORS.md | ⬜ Not started | | | |
| DEPLOYMENT_GUIDE.md | ⬜ Not started | | | Blocks enterprise adoption |
| DOCKER_SETUP.md | ⬜ Not started | | | |
| SECURITY_HARDENING.md | ⬜ Not started | | | Required for audits |
| CLI_REFERENCE.md | ⬜ Not started | | | Unblocks CLI users |
| DEVELOPER_SETUP.md | ⬜ Not started | | | Improves onboarding |
| CONTRIBUTING.md | ⬜ Not started | | | Enables contributions |
| Accuracy fixes | ⬜ Not started | | | Quick wins |
| [... remaining 48 docs ...] | | | | |

**How to use this:**
1. Copy this file to a project management tool (Jira, GitHub Projects, Trello)
2. Assign owners to each document
3. Update status (⬜ Not started → 🟨 In progress → ✅ Done)
4. Track due dates
5. Review weekly

---

## Success Metrics

**After P0 completion (week 2):**
- [ ] New developers can set up in 30 min without asking for help
- [ ] API clients have working examples for 90% of endpoints
- [ ] First contributor submits PR without questions about process
- [ ] Enterprise can follow deployment guide to production

**After P1 completion (week 4):**
- [ ] SOC 2 customer has documented roadmap to compliance
- [ ] AWS customer can deploy with confidence
- [ ] New connector can be added by following template

**After P2 completion (week 6):**
- [ ] Project has changelog, release process, and ADRs
- [ ] New team member can onboard in 1 day
- [ ] Security auditors have architecture and design docs

---

**Last Updated:** 2026-03-19
**Status:** Ready to start
