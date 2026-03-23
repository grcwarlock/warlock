# Warlock

**Pipeline-first GRC platform.** Compliance treated as a telemetry problem — not a spreadsheet problem.

Evidence flows through 4 immutable stages with SHA-256 integrity hashing at every step:

```
Stage 1: Connectors (165 sources) → RawEventData     → collect from cloud/EDR/IAM/SIEM APIs
Stage 2: Normalizers (165 parsers) → FindingData       → transform to universal findings
Stage 3: Control Mapper           → ControlMappingData → map to 1,996 controls across 14 frameworks
Stage 4: Assessor (Tier 1-4)      → ControlResultData  → deterministic assertions + AI reasoning
```

Every finding traces back to its raw API response. Every control result traces back to its finding. The hash-chained audit trail makes the entire chain tamper-evident.

## Frameworks

| Framework | Controls | Crosswalks | Status |
|---|---|---|---|
| NIST 800-53 Rev 5 | 1,176 | 1,843 edges | Full catalog (20 families + enhancements) |
| ISO 27001:2022 | 93 | | Complete Annex A |
| ISO 27701:2019 | 95 | | PIMS + Annex A + Annex B |
| ISO 42001:2023 | 39 | | AI Management System |
| SOC 2 (TSC) | 46 | | CC1-CC9, A1, C1, PI1, P1 |
| UCF (Unified) | 115 | | 20 domains, maps to all frameworks |
| FedRAMP Moderate | 26 | | NIST 800-53 overlay for cloud systems |
| HIPAA Security Rule | 64 | | Administrative, Physical, Technical safeguards |
| CMMC Level 2 | 110 | | 14 families aligned with NIST 800-171 |
| GDPR | 15 | | EU data protection regulation |
| PCI DSS v4.0 | 63 | | 12 requirements for cardholder data |
| NIST CSF 2.0 | 101 | | Govern, Identify, Protect, Detect, Respond, Recover |
| EU AI Act | 33 | | High-risk AI system requirements |
| SEC Cyber | 20 | | SEC cybersecurity disclosure rules |
| **Total** | **1,996** | **1,843** | Per-control monitoring frequencies (NIST 800-53A) |

## Connectors (165)

**Cloud:** AWS, Azure, GCP, OCI, IBM Cloud, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare, Linode/Akamai, Hetzner, Spot.io
**EDR:** CrowdStrike, Microsoft Defender, SentinelOne, Sophos, Tanium
**IAM:** Okta, Entra ID, CyberArk, SailPoint, HashiCorp Vault, JumpCloud, Auth0, Ping Identity, OneLogin
**Scanners:** Tenable, Qualys, Wiz, Rapid7 InsightVM, CrowdStrike Spotlight, Vulcan Cyber, Nessus
**CSPM:** Prisma Cloud, Orca Security, Lacework, Ermetic
**SIEM:** Sentinel, Splunk, Elastic, Sumo Logic, LogRhythm
**Network Security:** Palo Alto Networks, Fortinet FortiGate, Zscaler, Cisco Umbrella, Tailscale, Twingate, Banyan Security, Barracuda, F5 BIG-IP, Wallarm
**HRIS:** Workday, BambooHR, Gusto, Rippling, ADP, UKG, SAP SuccessFactors, Paylocity
**ITSM:** ServiceNow, ServiceNow GRC, ServiceNow CMDB, PagerDuty, Opsgenie, ManageEngine
**Training:** KnowBe4
**Code Security:** Snyk, Snyk Container, GitHub Advanced Security, Checkmarx, SonarQube, Semgrep, Trivy, GitGuardian, Veracode, FOSSA, Socket.dev, Chainguard, Syft/Grype
**DLP:** Microsoft Purview, Netskope, Nightfall AI, Code42 Incydr, Varonis, Rubrik Security Cloud
**Backup:** Veeam, AWS Backup, Commvault, Rubrik, Cohesity, Druva
**MDM:** Microsoft Intune, Jamf, Kandji, VMware Workspace ONE, Microsoft WSUS/SCCM, Ivanti Patch, Automox, Fleet
**MFA / Password:** Duo Security, 1Password, Bitwarden
**Collaboration:** Slack, Google Workspace, Salesforce, Microsoft Teams Compliance, Zoom, Smarsh
**DevOps:** GitLab, Jira, Ansible/AWX
**Observability:** Datadog, New Relic, Grafana, Kubecost, Infracost
**Cloud Threat:** AWS GuardDuty
**Email Security:** Proofpoint, Abnormal Security, Exchange Online, Mimecast
**GRC:** Confluence, OneTrust, Drata, Vanta, Archer, Secureframe
**Privacy:** TrustArc, Cookiebot, Osano
**Physical:** Verkada
**Third-Party Risk:** SecurityScorecard, BitSight
**Container:** Kubernetes, Aqua Security
**Infrastructure:** Terraform Cloud
**AI/ML:** MLflow, SageMaker, Databricks, Weights & Biases, Vertex AI
**CI/CD:** Jenkins, GitHub Actions, GitLab CI, CircleCI
**Secrets Management:** AWS Secrets Manager, Azure Key Vault, GCP Secret Manager
**Certificate Management:** Venafi, AWS ACM, DigiCert CertCentral
**Asset Discovery:** Axonius, runZero
**API Security:** Salt Security, Noname Security, 42Crunch
**Data Governance:** BigID
**Pentest Platforms:** Cobalt, HackerOne, PlexTrac
**Ingest:** Webhook (generic)

## Quick Start (Docker — recommended)

```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
docker compose up demo
```

That's it. Postgres, Redis, OPA, migrations, seed data, and API server — all in one command.

- API: http://localhost:8000/docs
- Login: admin@acme.com / WarlockAdmin2026!
- Stop: `docker compose down`
- Fresh reset: `docker compose down -v && docker compose up demo`

### Quick Start (local Python)

```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
./scripts/demo.sh
```

Requires Python 3.12+, creates a venv, seeds with SQLite. See **[DEMO.md](DEMO.md)** for details.

## CLI (556 leaf commands across 68 modules)

Warlock's CLI covers the full GRC lifecycle. See **[CLI-REFERENCE.md](CLI-REFERENCE.md)** for the complete command dictionary.

### Highlights

| Domain | Group | Commands | Description |
|---|---|---|---|
| **Pipeline** | `warlock collect`, `pipeline`, `automation` | 25 | Collect, normalize, map, assess, schedule, replay |
| **Connectors** | `warlock connectors` | 23 | List, test, validate, collect, health check all 165 connectors |
| **Findings** | `warlock findings`, `vulns` | 23 | List, search, suppress, export, aging, SLA, trends |
| **Compliance** | `warlock comply`, `frameworks`, `assertions` | 47 | Auto-map, gap analysis, readiness scores, maturity model |
| **Incidents** | `warlock incidents` | 11 | Create, triage, timeline, post-mortem, MTTR metrics |
| **Evidence** | `warlock evidence` | 17 | Attach, verify hash chain, package for auditors, freshness |
| **Risk** | `warlock risk`, `risk-engine` | 22 | FAIR quantification, Monte Carlo, risk register, appetite |
| **Privacy** | `warlock privacy` | 17 | DSAR lifecycle, breach notification, ROPA, data maps |
| **Governance** | `warlock poams`, `poam`, `changes`, `exceptions` | 20 | POA&M milestones, change management, policy exceptions |
| **Attestations** | `warlock attestations` | 8 | Create, sign, expiry tracking, audit report |
| **Audit** | `warlock audit`, `audit-trail` | 18 | Engagement management, hash chain verification, tamper detection |
| **Users** | `warlock users`, `sod` | 17 | RBAC, roles, scopes, segregation of duties analysis |
| **Vendors** | `warlock vendor-mgmt` | 16 | TPRM lifecycle, concentration risk, SOC 2 review, offboarding |
| **Reports** | `warlock reports` | 16 | Executive, board, KRI, KPI, ConMon, SLA, audit-readiness |
| **Dashboard** | `warlock dashboard` | 15 | Live terminal dashboard, KRI engine, posture, alerts |
| **Correlation** | `warlock correlate` | 15 | Trace findings to controls, blast radius, gap analysis |
| **Bulk Ops** | `warlock bulk` | 12 | Suppress, assign, close, deduplicate, reprocess at scale |
| **AI-Powered** | `warlock ai-ops` | 18 | Explain, root-cause, predict, draft POA&Ms, classify |
| **Lake Analytics** | `warlock lake-analytics` | 20 | SQL query, anomaly detection, trends, lineage, data quality |
| **OSCAL** | `warlock oscal` | 8 | Catalogs, profiles, SSP, assessment results, POA&M export |
| **Policies** | `warlock policies`, `policy` | 19 | OPA Rego management, lifecycle, review-due, coverage |
| **Other** | `calendar`, `training`, `bcp`, `conmon`, `terraform`, `integrations` | 32 | Cross-domain calendar, BCP/DR, continuous monitoring |

### Quick Examples

```bash
# Pipeline
warlock collect                              # full pipeline run
warlock connectors test-all                  # health check all connectors
warlock pipeline status                      # recent run status

# Compliance
warlock comply readiness-score nist_800_53   # 0-100 score with breakdown
warlock comply quick-wins --limit 10         # lowest-effort fixes
warlock frameworks gaps soc2                 # controls with no evidence

# Incidents & findings
warlock incidents create --severity critical --title "Data breach detected"
warlock findings aging --severity critical   # how old are critical findings?
warlock vulns sla-breach                     # vulns past SLA deadline

# Evidence & audit
warlock evidence freshness --threshold-days 30
warlock audit-trail tamper-detect            # scan for hash chain breaks
warlock evidence package soc2 --output /tmp  # auditor evidence bundle

# Risk & AI
warlock risk-engine simulate --iterations 10000
warlock ai-ops explain-finding <id> --ai     # AI explanation + remediation
warlock comply executive-brief --format md   # one-page brief

# Bulk operations
warlock bulk suppress --source nessus --severity info --reason "scanner noise"
warlock bulk link-findings-to-issues --auto  # auto-create issues for critical findings

# Dashboard
warlock dashboard live --refresh 30          # real-time terminal dashboard
warlock dashboard kri evaluate               # red/amber/green KRI status

# Cross-domain correlation
warlock correlate trace <finding_id>         # full provenance trace
warlock correlate blast-radius <finding_id>  # impact analysis
```

## REST API

```bash
# Start the API server
warlock-api
# or with docker
docker compose up demo

# Health & readiness
GET  /api/v1/health           # basic health check
GET  /api/v1/health/live      # liveness probe (Kubernetes)
GET  /api/v1/health/ready     # readiness probe (DB + scheduler check)

# Authentication
POST /api/v1/auth/login       # JWT bearer token
POST /api/v1/auth/register    # create user (admin only)
POST /api/v1/auth/logout      # revoke all tokens
POST /api/v1/auth/api-keys    # generate API key

# Pipeline
POST /api/v1/pipeline/collect # trigger pipeline run (background)
GET  /api/v1/pipeline/status  # run status + metrics

# Compliance data
GET  /api/v1/findings         # list/filter findings
GET  /api/v1/results          # control results
GET  /api/v1/results/coverage # compliance coverage
GET  /api/v1/results/posture  # posture scores

# Monitoring & trends
GET  /api/v1/cadence          # monitoring cadence status
GET  /api/v1/sufficiency      # evidence sufficiency scores
GET  /api/v1/posture/history  # posture time-series with trends
GET  /api/v1/effectiveness    # control effectiveness metrics
GET  /api/v1/drift            # compliance drift events
POST /api/v1/audit-simulation # project audit readiness

# Remediation
GET  /api/v1/poams            # POA&Ms
POST /api/v1/poams/{id}/extend # extend POA&M deadline
GET  /api/v1/compensating-controls
GET  /api/v1/risk-acceptances

# Audit & export
GET  /api/v1/engagements      # audit engagements
POST /api/v1/export/oscal     # OSCAL JSON export
POST /api/v1/engagements/{id}/binder  # audit evidence binder
POST /api/v1/frameworks/diff  # framework version comparison
POST /api/v1/impact-check     # compliance-as-code CI check

# GDPR
GET  /api/v1/gdpr/export      # data subject access (Article 15)
DELETE /api/v1/gdpr/erase     # PII anonymization (Article 17)

# Admin
GET  /api/v1/audit-trail      # immutable audit log
GET  /api/v1/audit-trail/verify # hash chain integrity check
```

## Security

- **Authentication:** JWT (HS256) + API keys (SHA-256 hashed, scoped)
- **Password hashing:** bcrypt (12 rounds) with PBKDF2 fallback (600K iterations)
- **Account lockout:** 5 failed attempts = 30-minute lock, timing-oracle prevention
- **Token revocation:** Per-user `token_valid_after` timestamp, logout endpoint
- **RBAC:** 4 roles (admin, auditor, owner, viewer) with attribute-based scoping
- **ABAC:** `allowed_frameworks`, `allowed_sources`, `allowed_control_families` per user
- **Rate limiting:** Sliding window with per-endpoint differentiation (login: 10/min)
- **Security headers:** HSTS, CSP, X-Frame-Options, nosniff, referrer policy
- **Audit trail:** Hash-chained, append-only, tamper-evident with verification endpoint
- **OPA integration:** Optional policy-as-code enforcement (fail-closed in production)

## Configuration

All configuration via environment variables with `WLK_` prefix. See `.env.example` for the complete reference.

```bash
# Core (required in production)
WLK_DATABASE_URL=postgresql://user:pass@localhost/warlock
WLK_JWT_SECRET=your-secret-here-min-32-chars    # REQUIRED in production
WLK_ENV=production                               # enforces security defaults

# AI (optional — enables Tier 2 reasoning + narrative generation)
WLK_AI_PROVIDER=ollama             # or anthropic, openai, gemini
WLK_AI_API_KEY=your-api-key        # set via env var, never hardcode
WLK_AI_MODEL=qwen3-coder:30b      # or claude-sonnet-4-20250514, gpt-4o
WLK_AI_BASE_URL=https://api.ollama.com  # or http://localhost:11434 for local
WLK_AI_CONFIDENCE_FLOOR=0.7        # reject low-confidence AI assessments
WLK_AI_TEMPERATURE=0.0             # deterministic for reproducibility

# Queue backend (production)
WLK_QUEUE_BACKEND=redis             # or kafka, sqs
WLK_QUEUE_URL=redis://localhost:6379

# Connectors (enable individually)
WLK_AWS_ENABLED=true
WLK_OKTA_ENABLED=true
WLK_OKTA_DOMAIN=your-org.okta.com
WLK_OKTA_API_TOKEN=...
```

## Architecture

```
warlock/
├── connectors/           # 165 source connectors (Stage 1)
├── normalizers/          # 165 normalizers (Stage 2)
├── mappers/              # Control mapping + crosswalking (Stage 3)
├── assessors/
│   ├── engine.py         # Tiered assessment (assertion -> AI -> inheritance)
│   ├── assertions.py     # 101 deterministic assertions across 14 control families
│   ├── ai_reasoning.py   # Tier 2: LLM evaluation with full compliance context
│   ├── ai_narrator.py    # SSP/POA&M narrative generation
│   ├── posture.py        # Posture aggregation, sufficiency scoring, time-series
│   ├── cadence.py        # Monitoring cadence tracking (NIST 800-53A frequencies)
│   ├── drift.py          # Compliance drift detection with change correlation
│   ├── simulation.py     # Audit readiness projection
│   ├── impact.py         # Compliance-as-code CI impact analysis
│   ├── risk_engine.py    # FAIR Monte Carlo risk quantification
│   └── vendor_risk.py    # Third-party risk scoring
├── pipeline/
│   ├── orchestrator.py   # 4-stage pipeline runner
│   ├── bus.py            # Event bus (pub/sub)
│   ├── queue.py          # Redis/Kafka/SQS backends
│   ├── scheduler.py      # Multi-schedule: collect, snapshot, cadence, retention
│   └── loader.py         # Bootstrap & registration
├── lake/                 # GRC Data Lake (23 modules)
│   ├── writer.py         # Event-sourced Parquet writer
│   ├── readers.py        # DuckDB analytical queries with ABAC
│   ├── zones.py          # Raw/enrichment/curated zone writers
│   ├── domains.py        # 10 curated domain writers
│   ├── query.py           # Embedded DuckDB query engine
│   ├── rag.py            # TF-IDF semantic search over curated zone
│   ├── catalog.py        # Iceberg table catalog
│   ├── bridges.py        # 6 bridge table writers
│   ├── scd.py            # SCD Type 2 dimension management
│   ├── reconciliation.py # OLTP/lake row count + hash comparison
│   ├── maintenance.py    # Compaction, snapshot expiry, orphan cleanup
│   └── ...               # + 12 more (ask, backfill, batch_assessor, consumption, etc.)
├── db/
│   ├── models.py         # 42 SQLAlchemy models
│   ├── migrations/       # Alembic migrations (16 revisions)
│   ├── audit.py          # Hash-chained audit trail
│   ├── repository.py     # Repository pattern
│   └── engine.py         # Session management
├── api/
│   ├── app.py            # FastAPI REST API
│   ├── auth.py           # JWT + API keys + RBAC + account lockout
│   ├── deps.py           # Auth dependencies + ABAC scoping
│   ├── middleware.py      # Rate limiting, security headers, audit logging
│   ├── policy_gate.py    # OPA policy enforcement
│   └── trust_portal.py   # Public trust portal
├── workflows/
│   ├── poam.py           # POA&M lifecycle management
│   ├── compensating.py   # Compensating control tracking
│   ├── risk_acceptance.py # Risk acceptance with AO approval
│   ├── inheritance.py    # Control inheritance (FedRAMP CRM)
│   ├── gdpr.py           # GDPR data subject rights (Articles 15-17)
│   ├── issues.py         # Issue tracking and remediation
│   ├── personnel.py      # HR + IdP + training cross-reference
│   └── retention.py      # Data retention with legal hold enforcement
├── export/
│   ├── oscal.py          # OSCAL 1.1.2 (AR, SSP, POA&M)
│   ├── binder.py         # Audit evidence binder (ZIP)
│   └── alerts.py         # Slack/PagerDuty/webhook routing
├── frameworks/           # 14 framework YAMLs (1,996 controls total)
│   ├── nist_800_53.yaml  # 1,176 controls with monitoring frequencies
│   ├── iso_27001.yaml    # 93 controls
│   ├── soc2.yaml         # 46 controls
│   ├── pci_dss.yaml      # 63 controls
│   ├── nist_csf.yaml     # 101 controls
│   ├── ...               # + 8 more (ISO 27701, ISO 42001, UCF, FedRAMP, HIPAA, CMMC, GDPR, EU AI Act, SEC Cyber)
│   ├── crosswalks.yaml   # 1,843 crosswalk edges
│   └── diff.py           # Framework version comparison
├── config.py             # Pydantic settings (WLK_* env vars)
├── domains/          # 7 domain service modules (registry, event bus, policy engine)
└── cli/              # Click CLI package (556 leaf commands, 68 modules)
```

## Database

42 tables across 16 Alembic migrations:

**Core pipeline:** ConnectorRun, RawEvent, Finding, ControlMapping, ControlResult
**Governance:** POAM, CompensatingControl, RiskAcceptance, ControlInheritance, SystemDependency
**Intelligence:** ChangeEvent, ComplianceDrift, PostureSnapshot
**Operations:** Issue, IssueComment, AuditEntry, AuditEngagement, Attestation, AuditComment
**Identity:** User, APIKey, ExternalAuditor, AuditorEngagementAssignment, EvidenceRequest
**Assets:** SystemProfile, Personnel, DataSilo, LegalHold, TrustAccessRequest, TrustDocument
**Configuration:** QuestionnaireTemplate, Questionnaire, RiskAnalysis, PolicyOverride
**Domain Architecture:** Policy, PolicyHistory, Asset, Vendor
**Operational:** Alert, Remediation, PipelineRun
**Search:** Embedding

## Tech Stack

- **Language:** Python 3.12+
- **Framework:** FastAPI + Uvicorn
- **ORM:** SQLAlchemy 2.0 + Alembic
- **Database:** SQLite (dev), PostgreSQL (prod) — generic JSON maps to JSONB
- **Queue:** Redis Streams / Kafka / SQS (pluggable)
- **Data Lake:** DuckDB + PyArrow + Parquet (analytical layer)
- **AI:** Anthropic, OpenAI, Gemini, Ollama (optional Tier 2 + narrative generation)
- **CLI:** Click + Rich
- **Validation:** Pydantic 2.0
- **HTTP:** httpx (async-capable)
- **Container:** Docker multi-stage build, docker-compose for local dev
- **CI/CD:** GitHub Actions (lint + test + build)

## Development

```bash
make install    # Install dev dependencies
make test       # Run tests
make lint       # Run ruff linter
make migrate    # Run Alembic migrations
make seed       # Populate demo data
make demo       # One-command full demo (DB + OPA + API + seed)
make dev        # Start docker-compose (postgres + redis + api)
make clean      # Tear down and clean up
```

## License

Proprietary. All rights reserved.
