# Warlock

**Pipeline-first GRC platform.** Compliance treated as a telemetry problem.

Data flows through 4 immutable stages:

```
Stage 1: Connectors (RawEventData)    → collect from 40 source APIs
Stage 2: Normalizers (FindingData)     → transform to universal findings
Stage 3: Mapper + Assessor            → map to controls, run assertions
Stage 4: Export                        → OSCAL, SOC 2 reports, ISO SoA, PDF
```

## Frameworks

| Framework | Controls | Status |
|---|---|---|
| NIST 800-53 Rev 5 | 1,176 | Full catalog (20 families + enhancements) |
| ISO 27001:2022 | 93 | Complete Annex A |
| ISO 27701:2019 | 95 | PIMS + Annex A + Annex B |
| ISO 42001:2023 | 39 | AI Management System |
| SOC 2 (TSC) | 46 | CC1–CC9, A1, C1, PI1, P1 |
| UCF (Unified) | 115 | 20 domains, maps to all frameworks |
| **Total** | **1,564** | 1,843 crosswalk edges |

## Connectors (40)

**Cloud:** AWS, Azure, GCP, OCI, IBM Cloud, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare

**EDR:** CrowdStrike, Microsoft Defender, SentinelOne

**IAM:** Okta, Entra ID, CyberArk, SailPoint, HashiCorp Vault

**Scanners:** Tenable, Qualys, Wiz

**CSPM:** Prisma Cloud

**SIEM:** Sentinel, Splunk, Elastic

**HRIS:** Workday

**ITSM:** ServiceNow

**Training:** KnowBe4

**Code Security:** Snyk, GitHub Advanced Security

**DLP:** Microsoft Purview

**Backup:** Veeam

**MDM:** Microsoft Intune

**GRC:** Confluence, OneTrust

**Physical:** Verkada

**Email:** Proofpoint

**Third-Party Risk:** SecurityScorecard

**Container:** Kubernetes

**AI Tracking:** MLflow

## Quick Start

```bash
# Install
pip install -e .

# Initialize database
warlock init

# Run pipeline (with connectors configured via env vars)
warlock collect

# View results
warlock results -f nist_800_53
warlock coverage

# Export OSCAL
warlock oscal --format ar -f nist_800_53 -o assessment.json
warlock oscal --format ssp -f iso_27001 --ai -o soa.json
warlock oscal --format poam -f soc2 -o remediation.json

# Risk quantification
warlock risk -f nist_800_53

# Policy coverage
warlock policy-coverage -f iso_27001

# Vendor risk
warlock vendors
```

## REST API

```bash
# Start the API server
warlock-api
# or
uvicorn warlock.api.app:app --host 0.0.0.0 --port 8000

# 32 endpoints including:
# POST /api/v1/auth/login          — JWT authentication
# POST /api/v1/pipeline/collect    — trigger pipeline run
# GET  /api/v1/results/posture     — control posture scores
# GET  /api/v1/results/coverage    — compliance coverage
# GET  /api/v1/export/oscal        — OSCAL export
# POST /api/v1/risk/analyze        — FAIR risk quantification
# GET  /api/v1/vendors/risk        — vendor risk scores
# GET  /api/v1/policies/coverage   — policy document coverage
# GET  /api/v1/engagements/{id}/package — audit evidence package
```

## Configuration

All configuration via environment variables with `WLK_` prefix:

```bash
# Database
WLK_DATABASE_URL=postgresql://user:pass@localhost/warlock

# AI (optional — enables Tier 2 reasoning + narrative generation)
WLK_AI_PROVIDER=anthropic    # or openai, gemini, ollama
WLK_AI_API_KEY=sk-...
WLK_AI_MODEL=claude-sonnet-4-20250514

# JWT (required for API)
WLK_JWT_SECRET=your-secret-here-min-32-chars

# Queue backend (optional — production)
WLK_QUEUE_BACKEND=redis      # or kafka, sqs
WLK_QUEUE_URL=redis://localhost:6379

# Connectors (enable individually)
WLK_AWS_ENABLED=true
WLK_AWS_REGIONS=us-east-1,us-west-2
WLK_OKTA_ENABLED=true
WLK_OKTA_DOMAIN=your-org.okta.com
WLK_OKTA_API_TOKEN=...
# ... see config.py for all options
```

## Architecture

```
warlock/
├── connectors/        # 40 source connectors (Stage 1)
├── normalizers/       # 41 normalizers (Stage 2)
├── mappers/           # Control mapping engine (Stage 3)
├── assessors/
│   ├── assertions.py  # 25 deterministic assertions
│   ├── engine.py      # Assessment engine + control inheritance
│   ├── ai_reasoning.py    # Tier 2: LLM-based evaluation
│   ├── ai_narrator.py     # Framework-aware narrative generation
│   ├── anomaly.py         # Tier 3: Drift/volume/access detection
│   ├── rag.py             # Tier 4: Semantic control matching
│   ├── posture.py         # Control posture aggregation
│   ├── risk_engine.py     # FAIR Monte Carlo risk quantification
│   ├── vendor_risk.py     # Third-party risk scoring
│   └── policy_discovery.py # Policy document scanning
├── pipeline/
│   ├── orchestrator.py    # 4-stage pipeline runner
│   ├── bus.py             # Event bus (pub/sub)
│   ├── queue.py           # Redis/Kafka/SQS backends
│   └── loader.py          # Bootstrap & registration
├── db/
│   ├── models.py          # 11 SQLAlchemy models
│   ├── audit.py           # Hash-chained audit trail
│   ├── repository.py      # Repository pattern
│   └── engine.py          # Session management
├── api/
│   ├── app.py             # FastAPI (32 routes)
│   ├── auth.py            # JWT + API keys + RBAC
│   ├── deps.py            # Auth dependencies
│   └── middleware.py       # Rate limiting, security headers
├── export/
│   ├── oscal.py           # OSCAL 1.1.2 (AR, SSP, POA&M)
│   ├── reports.py         # SOC 2 Type II, ISO SoA, PDF
│   ├── temporal.py        # Audit-period evidence packaging
│   ├── auditor.py         # Auditor evidence workflow
│   └── alerts.py          # Slack/PagerDuty/webhook routing
├── frameworks/            # 6 framework YAMLs + crosswalks
└── cli.py                 # Click CLI
```

## Tech Stack

- Python 3.12+
- SQLAlchemy 2.0 (SQLite dev, PostgreSQL prod)
- FastAPI + Uvicorn
- httpx (all HTTP calls)
- Pydantic 2.0 (settings + validation)
- Click + Rich (CLI)

## License

Proprietary. All rights reserved.
