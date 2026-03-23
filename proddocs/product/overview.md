# Warlock Product Overview

## What Warlock Is

Warlock is a pipeline-first Governance, Risk, and Compliance (GRC) platform that treats compliance as a telemetry problem, not a spreadsheet problem.

Instead of point-in-time audits and manual evidence collection, Warlock continuously ingests security telemetry from your existing tools, normalizes it into a universal finding format, maps findings to compliance controls across 14 frameworks, and produces auditable assessment results -- all through an immutable, hash-chained pipeline.

The result: compliance posture that updates in real time, evidence that traces back to raw API responses, and assessment results that auditors can independently verify.

## The Problem Warlock Solves

Traditional GRC workflows are broken in three fundamental ways:

**Evidence is manual.** Compliance teams spend weeks collecting screenshots, exporting CSVs, and pasting them into spreadsheets. By the time the evidence binder is assembled, half of it is already stale.

**Assessment is subjective.** Two auditors reviewing the same control can reach different conclusions because there is no deterministic logic, no shared assertion library, and no machine-readable definition of "compliant."

**Traceability is absent.** When an auditor asks "why is AC-2 marked compliant?", the answer should not require a human to reconstruct the chain from raw data to finding to control result. The answer should be embedded in the data itself.

Warlock eliminates all three problems by replacing manual processes with an automated, four-stage pipeline.

## How It Works

Evidence flows through four immutable stages, each producing SHA-256 integrity hashes:

```
Stage 1: Connectors (165 sources)  --> RawEventData      Collect from cloud/EDR/IAM/SIEM APIs
Stage 2: Normalizers (165 parsers) --> FindingData        Transform to universal findings
Stage 3: Control Mapper            --> ControlMappingData  Map to 1,996 controls across 14 frameworks
Stage 4: Assessor (Tier 1-4)       --> ControlResultData   Deterministic assertions + AI reasoning
```

Every finding traces back to its raw API response. Every control result traces back to its finding. The hash-chained audit trail makes the entire chain tamper-evident.

### Stage 1: Collection

165 source connectors pull security telemetry from the tools your organization already uses -- cloud providers (AWS, Azure, GCP), identity providers (Okta, Entra ID), EDR platforms (CrowdStrike, SentinelOne), vulnerability scanners (Tenable, Qualys, Wiz), and dozens more. Each connector validates its configuration, verifies connectivity via health check, and produces raw events with the verbatim API response preserved.

### Stage 2: Normalization

Each raw event passes through a matching normalizer that transforms provider-specific data into a universal `FindingData` format. An AWS IAM credential report, an Okta user list, and an Entra ID directory export all become the same structured finding type -- enabling cross-provider analysis and unified control mapping.

### Stage 3: Control Mapping

Normalized findings are mapped to specific controls across all 14 compliance frameworks. A single finding about MFA status can map to NIST 800-53 AC-2, SOC 2 CC6.1, ISO 27001 A.8.5, HIPAA 164.312(d), and PCI DSS 8.3 simultaneously. 1,843 crosswalk edges link related controls across frameworks, so evidence collected for one framework automatically satisfies overlapping requirements in others.

### Stage 4: Assessment

A four-tier assessment model evaluates each control:

1. **Deterministic assertions** (101 functions) -- fast, auditable, reproducible checks like "MFA is enabled" or "no open security groups"
2. **AI reasoning** -- LLM-powered evaluation for controls where assertions are unavailable or inconclusive, with a configurable confidence floor
3. **OPA Rego policies** (670 policies) -- policy-as-code evaluation across 8 frameworks
4. **Control inheritance** -- parent-to-child status inheritance following the FedRAMP CRM pattern, where child enhancement controls inherit their parent's status

## Key Capabilities

### Continuous Compliance Monitoring

Warlock runs on a configurable schedule -- not just during audit season. The built-in scheduler supports multiple cadences: collection runs, posture snapshots, cadence checks, and retention management. Controls have monitoring frequencies defined per the NIST 800-53A standard (daily, weekly, monthly, quarterly), and Warlock tracks whether each control is being assessed on schedule.

### 14 Compliance Frameworks, 1,996 Controls

| Framework | Controls | Who Needs It |
|---|---|---|
| NIST 800-53 Rev 5 | 1,176 | Federal agencies, FedRAMP, defense contractors |
| ISO 27001:2022 | 93 | Any organization seeking ISMS certification |
| ISO 27701:2019 | 95 | Organizations processing personal data |
| ISO 42001:2023 | 39 | Organizations developing or deploying AI systems |
| SOC 2 (TSC) | 46 | SaaS companies, service providers |
| UCF (Unified) | 115 | Organizations managing multiple frameworks |
| FedRAMP Moderate | 26 | Cloud service providers selling to US government |
| HIPAA Security Rule | 64 | Healthcare organizations and business associates |
| CMMC Level 2 | 110 | Defense industrial base contractors |
| GDPR | 15 | Organizations processing EU personal data |
| PCI DSS v4.0 | 63 | Organizations handling payment card data |
| NIST CSF 2.0 | 101 | Any organization building a cybersecurity program |
| EU AI Act | 33 | Organizations deploying high-risk AI in the EU |
| SEC Cyber | 20 | Public companies subject to SEC disclosure rules |

Crosswalks (1,843 edges) connect related controls across frameworks. Assess once for NIST 800-53 AC-2, and the result automatically propagates to SOC 2 CC6.1, ISO 27001 A.8.5, and every other framework with an equivalent control.

### Remediation Workflows

When controls fail assessment, Warlock creates actionable remediation paths:

- **Plans of Action and Milestones (POA&Ms)** -- track remediation with deadlines, assignments, and state machine transitions
- **Compensating controls** -- document alternative controls when primary controls cannot be fully implemented
- **Risk acceptances** -- formal risk acceptance with Authorizing Official approval and expiration tracking
- **Issues** -- auto-created from non-compliant results, with comment threads and assignment

### OSCAL Export and Audit Evidence

Warlock exports compliance data in OSCAL 1.1.2 format (Assessment Results, System Security Plan, POA&M). The audit evidence binder packages findings, results, and supporting data into a ZIP archive organized per engagement. AI-generated SSP narratives are available when an LLM provider is configured.

### Risk Quantification

The built-in FAIR Monte Carlo risk engine quantifies risk in financial terms. Vendor risk scoring evaluates third-party exposure. The audit simulation projects readiness at a future date, answering "if we audit on September 1, what will our posture look like?"

### GRC Data Lake

An analytical layer built on DuckDB and Parquet enables complex queries across the full compliance dataset. The data lake supports:

- **Three zones**: raw (verbatim events), enrichment (normalized + mapped), curated (domain-specific analytical tables)
- **RAG search**: TF-IDF semantic search over the curated zone for natural language compliance queries
- **Batch AI assessment**: Post-pipeline AI evaluation across the curated zone
- **Reconciliation**: Automated comparison between OLTP and lake data for integrity verification

## Target Users

### Compliance Teams
Run the pipeline, review results, manage POA&Ms, prepare for audits. The CLI and API both provide filtered views by framework, status, and control family. Evidence sufficiency scoring identifies gaps before auditors do.

### Security Engineers
Configure connectors for your security tooling, write custom assertions for organization-specific controls, define OPA policies for automated enforcement. The event-sourced architecture means every compliance decision has a clear technical explanation.

### CISOs and Risk Managers
Track posture trends over time, quantify risk using FAIR methodology, monitor compliance drift with correlated change detection. The posture history and effectiveness metrics provide board-ready reporting.

### Auditors
Verify the hash-chained audit trail independently. OSCAL exports provide machine-readable assessment results. The audit evidence binder packages all supporting documentation per engagement. A public trust portal can expose compliance status to external parties.

## Key Differentiators

### Hash-Chained Audit Trail
SHA-256 hashing at every pipeline stage creates a tamper-evident chain from raw API response to control result. The verification endpoint confirms chain integrity programmatically -- no manual spot-checking required.

### Event-Sourced Compliance
Every compliance state change is an event. Warlock does not overwrite previous assessments -- it appends new ones. This means you can reconstruct compliance posture at any point in time, track exactly when a control drifted, and prove to auditors that a control was compliant on a specific date.

### Fail-Closed Security Model
OPA policy gates, assertion evaluation, and ABAC scoping all default to deny. If the policy engine is unreachable, access is denied. If an assertion encounters unexpected data, it fails the control. If a user's scope does not include a framework, they cannot see its results. This is the opposite of most GRC tools, which default to "everything is accessible."

### AI-Augmented, Not AI-Dependent
AI reasoning is Tier 2, not Tier 1. Deterministic assertions run first and cover the majority of controls. AI fills gaps where assertions are unavailable, with a configurable confidence floor (default 0.7) that rejects unreliable assessments. The AI provider is pluggable -- Anthropic, OpenAI, Gemini, or Ollama (local).

### Multi-Framework Crosswalking
A single body of evidence satisfies controls across all 14 frameworks simultaneously. Organizations undergoing multiple certifications (SOC 2 + ISO 27001 + HIPAA is common) collect evidence once and map it everywhere. The crosswalk graph has 1,843 edges connecting equivalent controls.

## Architecture Summary

Warlock is a Python 3.12+ application with these core components:

| Component | Technology | Purpose |
|---|---|---|
| API | FastAPI + Uvicorn | 163 REST endpoints, ABAC-scoped |
| CLI | Click + Rich | 599 leaf commands across 68 modules |
| Database | SQLAlchemy 2.0 | 42 models, schema via Base.metadata.create_all() |
| Data Lake | DuckDB + PyArrow + Parquet | Analytical queries over compliance data |
| Queue | Redis / Kafka / SQS (pluggable) | Pipeline job distribution |
| AI | Anthropic / OpenAI / Gemini / Ollama | Tier 2 reasoning + narrative generation |
| Policy Engine | OPA / Rego | 670 policies for compliance-as-code |
| Infrastructure | Terraform | 12 IaC modules (AWS, Azure, GCP) |

The platform supports SQLite for development and PostgreSQL for production. Docker Compose provides a one-command local environment with all dependencies.

## Deployment Options

**Docker (recommended for evaluation)**:
```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
docker compose up demo
```

This starts PostgreSQL, Redis, OPA, runs migrations, seeds demo data (165 connectors, ~5,475 findings, 373,000+ control results), and serves the API.

**Local Python (development)**:
```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
./scripts/demo.sh
```

Requires Python 3.12+. Creates a virtualenv, seeds with SQLite.

**Production**: Deploy with environment variables prefixed `WLK_`. Configure `WLK_DATABASE_URL` (PostgreSQL), `WLK_JWT_SECRET` (32+ characters), `WLK_ENV=production`, and enable specific connectors by setting their API credentials.

## Security Model

- **Authentication**: JWT (HS256) + API keys (SHA-256 hashed, scoped)
- **Password hashing**: bcrypt (12 rounds) with PBKDF2 fallback
- **Account lockout**: 5 failed attempts trigger a 30-minute lock
- **RBAC**: 4 roles -- admin, auditor, owner, viewer
- **ABAC**: Per-user scoping by framework, source, and control family
- **Rate limiting**: Sliding window with per-endpoint differentiation
- **Security headers**: HSTS, CSP, X-Frame-Options, nosniff
- **GDPR compliance**: Data subject access (Article 15) and PII anonymization (Article 17) endpoints
