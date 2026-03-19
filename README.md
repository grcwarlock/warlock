# Warlock

**Pipeline-first GRC platform.** Compliance treated as a telemetry problem — not a spreadsheet problem.

Evidence flows through 4 immutable stages with SHA-256 integrity hashing at every step:

```
Stage 1: Connectors (40 sources)  → RawEventData     → collect from cloud/EDR/IAM/SIEM APIs
Stage 2: Normalizers (41 parsers) → FindingData       → transform to universal findings
Stage 3: Control Mapper           → ControlMappingData → map to 1,564 controls across 6 frameworks
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
| **Total** | **1,564** | **1,843** | Per-control monitoring frequencies (NIST 800-53A) |

## Connectors (40)

**Cloud:** AWS, Azure, GCP, OCI, IBM Cloud, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare
**EDR:** CrowdStrike, Microsoft Defender, SentinelOne
**IAM:** Okta, Entra ID, CyberArk, SailPoint, HashiCorp Vault
**Scanners:** Tenable, Qualys, Wiz
**CSPM:** Prisma Cloud
**SIEM:** Sentinel, Splunk, Elastic
**HRIS:** Workday | **ITSM:** ServiceNow | **Training:** KnowBe4
**Code Security:** Snyk, GitHub Advanced Security
**DLP:** Microsoft Purview | **Backup:** Veeam | **MDM:** Microsoft Intune
**GRC:** Confluence, OneTrust | **Physical:** Verkada | **Email:** Proofpoint
**Third-Party Risk:** SecurityScorecard | **Container:** Kubernetes | **AI Tracking:** MLflow

## Quick Start

```bash
# Install (Python 3.12+)
make install
# or manually:
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"

# Initialize the database
make migrate

# Seed the full demo environment (no credentials or API keys needed)
make seed

# Explore
warlock coverage                       # compliance summary across 6 frameworks
warlock results --status non_compliant # non-compliant findings
warlock findings                       # all 547 normalized findings
warlock sources                        # 40 connectors + 41 normalizers
warlock systems                        # 5 system profiles (FIPS 199 boundaries)
warlock personnel                      # 50 personnel with compliance flags
warlock vendors                        # vendor risk scores from SecurityScorecard
warlock questionnaires                 # vendor assessment questionnaires
warlock data-silos                     # 12 storage locations with classification
warlock issues                         # 541 compliance issues
warlock policy-coverage -f iso_27001   # policy documentation gaps
warlock risk -f nist_800_53            # FAIR Monte Carlo risk analysis
warlock oscal                          # OSCAL JSON export
```

### Monitoring & Trends

```bash
warlock cadence                        # monitoring cadence status
warlock sufficiency                    # evidence sufficiency gaps
warlock posture-history -f nist_800_53 # 30-day posture trends
warlock effectiveness                  # control effectiveness (uptime %, MTTR)
warlock drift                          # compliance drift with correlated changes
warlock simulate-audit -f soc2 --date 2026-09-01  # audit readiness projection
```

### Remediation Workflows

```bash
warlock poams                          # POA&M tracking
warlock poams --overdue                # overdue POA&Ms
warlock compensating-controls          # active compensating controls
warlock risk-acceptances               # formal risk acceptances
warlock inheritance --system APP       # control inheritance by system acronym or UUID
warlock dependencies                   # cross-system dependency graph
```

### Docker Quick Start

```bash
make dev    # Starts PostgreSQL + Redis + API via docker-compose
# API available at http://localhost:8000/api/v1/health
```

## Demo Environment

`make seed` runs `scripts/demo_seed.py` which builds a full-stack Fortune 500 compliance environment. No real API credentials are needed — 40 mock connectors produce realistic events that flow through the real pipeline (collect -> normalize -> map -> assess).

### Seeding from Scratch

```bash
# Option 1: Makefile (recommended)
make clean && make migrate && make seed

# Option 2: Manual
rm -f warlock.db                       # remove existing DB
alembic upgrade head                   # apply all migrations
python scripts/demo_seed.py            # run the full seed
```

The seed script runs in ~7 seconds and outputs progress for each phase:

```
[1/20] Initializing database...
[2/20] Loading frameworks, assertions, and normalizers...
[3/20] Running pipeline (collect -> normalize -> map -> assess)...
[4/20] Done with pipeline!
------------------------------------------------------------
  Raw events collected:   191
  Findings normalized:    547
  Controls mapped:        26,135
  Results assessed:       26,135
  Connectors succeeded:   40
  Connectors failed:      0
  Duration:               7.53s
------------------------------------------------------------
```

### What Gets Seeded

**Pipeline data** (from 40 connectors exercising all 41 normalizers and all 25 assertions):

| Data | Count | Details |
|---|---|---|
| Raw events | 191 | From 40 connectors across 17 source types |
| Findings | 547+ | 547 from pipeline + vendor risk findings from `warlock vendors` |
| Control results | 26,135 | Mapped across all 6 frameworks |
| Assertions exercised | 25/25 | Every deterministic assertion fires at least once |

**Framework coverage:**

| Framework | Compliant | Non-Compliant | Not Assessed | Total |
|---|---|---|---|---|
| NIST 800-53 | 624 | 187 | 18,525 | 19,336 |
| ISO 27001 | 783 | 147 | 1,031 | 1,961 |
| ISO 27701 | 116 | 60 | 1,326 | 1,502 |
| ISO 42001 | 131 | 11 | 581 | 723 |
| SOC 2 | 455 | 84 | 585 | 1,124 |
| UCF | 107 | 49 | 1,333 | 1,489 |

**Connectors by category (all 40 exercised):**

| Category | Connectors |
|---|---|
| Cloud (10) | AWS, Azure, GCP, OCI, IBM Cloud, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare |
| IAM (5) | Okta, Entra ID, CyberArk, SailPoint, HashiCorp Vault |
| EDR (3) | CrowdStrike, Microsoft Defender, SentinelOne |
| SIEM (3) | Azure Sentinel, Splunk, Elastic |
| Scanners (3) | Tenable, Qualys, Wiz |
| CSPM (1) | Prisma Cloud |
| MDM (1) | Microsoft Intune |
| ITSM (1) | ServiceNow |
| HRIS (1) | Workday |
| Training (1) | KnowBe4 |
| Code (2) | Snyk, GitHub Advanced Security |
| DLP (1) | Microsoft Purview |
| Backup (1) | Veeam |
| Email (1) | Proofpoint |
| GRC (2) | Confluence, OneTrust |
| Physical (1) | Verkada |
| AI Tracking (1) | MLflow |
| Third-Party Risk (1) | SecurityScorecard |
| Container (1) | Kubernetes |

**Governance & lifecycle data:**

| Data | Count | Details |
|---|---|---|
| System profiles | 5 | APP, CDW, CIT, AIML, DEV with FIPS 199 categorization |
| Personnel | 50 | 10 departments, MFA flags, training status, risk scores |
| Data silos | 12 | S3, RDS, Redshift, SharePoint, GitHub repos, multi-cloud |
| Issues | 530+ | Auto-created from non-compliant results + 3 manual |
| POA&Ms | 18 | 5 draft, 4 open, 3 in-progress, 2 completed, 2 overdue |
| Compensating controls | 10 | 5 active, 2 proposed, 2 approved, 1 expired |
| Risk acceptances | 7 | With AO approval and expiry tracking |
| Control inheritances | 70 | Inherited/shared/common/system-specific per FedRAMP CRM |
| System dependencies | 6 | Identity, application, infrastructure dependency chains |
| Change events | 40 | CloudTrail + GitHub + ServiceNow over 30 days |
| Posture snapshots | 360 | 30 days x 12 controls with improving/degrading/stable trends |
| Compliance drifts | 10 | With correlated change events and confidence scores |
| Audit engagements | 2 | With external auditors, assignments, and evidence requests |
| Legal holds | 2 | Active FTC investigation + completed SOC 2 preservation |
| Policy overrides | 3 | Break-glass, auditor scope, and POAM approval rules |
| Vendor questionnaires | 2 | SIG and DDQ templates with in-progress responses |
| Demo users | 4 | admin, auditor, owner, viewer roles for API testing |

### Re-seeding

To reset and re-seed, delete the database and re-run:

```bash
make clean && make migrate && make seed
```

Or without Docker:

```bash
rm -f warlock.db && alembic upgrade head && python scripts/demo_seed.py
```

### Verifying the Seed

After seeding, run the test suite to confirm nothing is broken:

```bash
make test    # 172 tests should pass
```

Quick smoke test for the seeded data:

```bash
warlock coverage                       # should show 6 frameworks with results
warlock sources                        # should show 40 connectors + 41 normalizers
warlock findings                       # should show findings from diverse sources
warlock inheritance --system APP       # should show control inheritance for Acme Production
```

## CLI Commands

### Pipeline & Monitoring

| Command | Description |
|---|---|
| `warlock collect` | Run the full pipeline: collect -> normalize -> map -> assess |
| `warlock collect -s aws` | Limit collection to specific source(s) |
| `warlock cadence` | Check monitoring cadence — are controls assessed on schedule? |
| `warlock cadence -f nist_800_53 --stale-only` | Show only stale controls |
| `warlock sufficiency -f soc2 --below 60` | Evidence sufficiency gaps |
| `warlock posture-history -f nist_800_53` | Posture score trends with trend arrows |
| `warlock effectiveness -f nist_800_53` | Control effectiveness (uptime %, MTTR, drift count) |

### Compliance Results

| Command | Description |
|---|---|
| `warlock results` | Control results from the last pipeline run |
| `warlock results -f nist_800_53 --status non_compliant` | Filter by framework/status |
| `warlock coverage` | Compliance coverage summary by framework |
| `warlock findings` | Normalized findings |
| `warlock drift` | Compliance drift events with correlated changes |
| `warlock simulate-audit -f soc2 --date 2026-09-01` | Project audit readiness at a future date |

### Remediation Workflows

| Command | Description |
|---|---|
| `warlock poams` | List Plans of Action & Milestones |
| `warlock poams --overdue` | Show overdue POA&Ms |
| `warlock compensating-controls` | List compensating controls |
| `warlock risk-acceptances` | List risk acceptances |
| `warlock risk-acceptances --expiring-soon 30` | Expiring within 30 days |
| `warlock issues` | Compliance issues |
| `warlock issues-auto-create` | Auto-create issues from non-compliant results |

### Enterprise & Governance

| Command | Description |
|---|---|
| `warlock systems` | System profiles (authorization boundaries) |
| `warlock inheritance --system <id-or-acronym>` | Control inheritance map for a system |
| `warlock dependencies` | Cross-system dependency graph |
| `warlock personnel --flagged` | Personnel with compliance flags |
| `warlock framework-diff --old v5.yaml --new v6.yaml` | Compare framework versions |

### Export & Risk

| Command | Description |
|---|---|
| `warlock oscal` | OSCAL JSON export (AR, SSP, POA&M) |
| `warlock oscal --format ssp -f nist_800_53 --ai` | AI-generated SSP narratives |
| `warlock risk -f nist_800_53` | FAIR Monte Carlo risk quantification |
| `warlock vendors` | Vendor risk scores |
| `warlock export binder --engagement <id>` | Audit evidence binder (ZIP) |

### Operations

| Command | Description |
|---|---|
| `warlock scheduler start` | Start continuous pipeline scheduler |
| `warlock scheduler status` | Show scheduler status (multi-schedule) |
| `warlock retention report` | Retention report (record ages, purgeable counts) |
| `warlock retention purge --execute` | Purge expired records (respects legal holds) |

## REST API

```bash
# Start the API server
warlock-api
# or with docker
docker compose up api

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
WLK_AI_PROVIDER=anthropic          # or openai, gemini, ollama
WLK_AI_API_KEY=sk-...
WLK_AI_MODEL=claude-sonnet-4-20250514
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
├── connectors/           # 40 source connectors (Stage 1)
├── normalizers/          # 41 normalizers (Stage 2)
├── mappers/              # Control mapping + crosswalking (Stage 3)
├── assessors/
│   ├── engine.py         # Tiered assessment (assertion -> AI -> inheritance)
│   ├── assertions.py     # 25 deterministic assertions bound to 99 controls
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
├── db/
│   ├── models.py         # 33 SQLAlchemy models
│   ├── migrations/       # Alembic migrations (7 revisions)
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
├── frameworks/
│   ├── nist_800_53.yaml  # 1,176 controls with monitoring frequencies
│   ├── iso_27001.yaml    # 93 controls
│   ├── soc2.yaml         # 46 controls
│   ├── crosswalks.yaml   # 1,843 crosswalk edges
│   └── diff.py           # Framework version comparison
├── config.py             # Pydantic settings (WLK_* env vars)
└── cli.py                # Click CLI
```

## Database

33 tables across 7 Alembic migrations:

**Core pipeline:** ConnectorRun, RawEvent, Finding, ControlMapping, ControlResult
**Governance:** POAM, CompensatingControl, RiskAcceptance, ControlInheritance, SystemDependency
**Intelligence:** ChangeEvent, ComplianceDrift, PostureSnapshot
**Operations:** Issue, IssueComment, AuditEntry, AuditEngagement, Attestation, AuditComment
**Identity:** User, APIKey, ExternalAuditor, AuditorEngagementAssignment, EvidenceRequest
**Assets:** SystemProfile, Personnel, DataSilo, LegalHold, TrustAccessRequest
**Configuration:** QuestionnaireTemplate, Questionnaire, RiskAnalysis, PolicyOverride

## Tech Stack

- **Language:** Python 3.12+
- **Framework:** FastAPI + Uvicorn
- **ORM:** SQLAlchemy 2.0 + Alembic
- **Database:** SQLite (dev), PostgreSQL (prod) — generic JSON maps to JSONB
- **Queue:** Redis Streams / Kafka / SQS (pluggable)
- **AI:** Anthropic, OpenAI, Gemini, Ollama (optional Tier 2 + narrative generation)
- **CLI:** Click + Rich
- **Validation:** Pydantic 2.0
- **HTTP:** httpx (async-capable)
- **Container:** Docker multi-stage build, docker-compose for local dev
- **CI/CD:** GitHub Actions (lint + test + build)

## Development

```bash
make install    # Install dev dependencies
make test       # Run 172 tests
make lint       # Run ruff linter
make migrate    # Run Alembic migrations
make seed       # Populate demo data
make dev        # Start docker-compose (postgres + redis + api)
make clean      # Tear down and clean up
```

## License

Proprietary. All rights reserved.
