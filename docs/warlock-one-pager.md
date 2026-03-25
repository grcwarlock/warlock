# Warlock — Pipeline-First GRC Platform

## The Problem

Compliance is still done in spreadsheets. Evidence is collected manually, assessments are subjective, and by the time an audit binder is assembled, half of it is stale. When an auditor asks "why is this control compliant?", nobody can trace the answer back to raw data without hours of reconstruction.

## What Warlock Does

Warlock treats compliance as a telemetry problem. It continuously ingests security data from the tools you already use, normalizes it, maps it to compliance controls, and produces auditable results — automatically, with a tamper-evident audit trail.

```
166 Connectors → Normalize → Map to 1,996 Controls → Assess → Report
                  SHA-256 integrity hashing at every stage
```

## Four Pipeline Stages

| Stage | What Happens | Output |
|-------|-------------|--------|
| **Collect** | Pull data from 166 sources (cloud, identity, EDR, scanners, HRIS, code security, etc.) | Raw events with verbatim API responses |
| **Normalize** | Transform provider-specific data into a universal finding format with automatic PII scrubbing | Clean, structured findings |
| **Map** | Map findings to controls across 14 compliance frameworks via 196 crosswalk edges | Control mappings (assess once, satisfy many frameworks) |
| **Assess** | Evaluate controls using deterministic assertions, AI reasoning, OPA policies, and control inheritance | Auditable pass/fail results with full evidence chain |

## 14 Frameworks, 1,996 Controls

NIST 800-53 (1,176) | ISO 27001 (93) | ISO 27701 (95) | ISO 42001 (39) | SOC 2 (46) | UCF (115) | FedRAMP (26) | HIPAA (64) | CMMC L2 (110) | GDPR (15) | PCI DSS v4.0 (63) | NIST CSF 2.0 (101) | EU AI Act (33) | SEC Cyber (20)

Crosswalks mean evidence collected for one framework automatically satisfies overlapping controls in others. One body of evidence, all frameworks.

## 166 Source Connectors

Cloud (AWS, Azure, GCP, OCI, IBM, Alibaba, DigitalOcean, Huawei, OVH, Cloudflare) | Identity (Okta, Entra ID, CyberArk, SailPoint, Vault, JumpCloud, Auth0) | EDR (CrowdStrike, Defender, SentinelOne, Sophos) | Scanners (Tenable, Qualys, Wiz, Nessus) | Code Security (Snyk, GitHub, Checkmarx, SonarQube, Semgrep, Trivy, GitGuardian, Veracode) | SIEM (Sentinel, Splunk, Elastic) | Network (Palo Alto, Fortinet, Zscaler) | HRIS (Workday, BambooHR, Gusto, Rippling) | CI/CD (Jenkins, GitHub Actions, GitLab CI, CircleCI) | and 20+ more across DLP, MDM, backup, email security, observability, GRC, and physical security.

## Assessment Engine

| Tier | Method | Coverage |
|------|--------|----------|
| 1 | **Deterministic assertions** (102 functions) | Fast, reproducible, auditable checks |
| 2 | **AI reasoning** (Anthropic, OpenAI, Gemini, Ollama) | Fills gaps with configurable confidence floor |
| 3 | **OPA/Rego policies** (670 policies across 8 frameworks) | Policy-as-code compliance evaluation |
| 4 | **Control inheritance** (FedRAMP CRM pattern) | Parent-to-child status propagation |

## Key Capabilities

- **Hash-chained audit trail** — SHA-256 at every stage; tamper-evident from raw API response to control result
- **Continuous monitoring** — scheduled pipeline runs with per-control monitoring frequencies (daily/weekly/monthly/quarterly per NIST 800-53A)
- **PII scrubbing at ingest** — personal data is detected, pseudonymized, and flagged before it reaches the database or any export
- **Remediation workflows** — POA&Ms, compensating controls, risk acceptances, and issue tracking with state machine transitions
- **OSCAL export** — machine-readable Assessment Results, SSP, and POA&M in OSCAL 1.1.2 format
- **GRC data lake** — DuckDB/Parquet analytical layer with raw, enrichment, and curated zones plus RAG search
- **Risk quantification** — FAIR Monte Carlo engine, vendor risk scoring, audit simulation
- **Multi-framework crosswalking** — 196 edges connecting equivalent controls; assess once, satisfy everywhere
- **Fail-closed security** — OPA gates, assertions, and ABAC all default to deny

## Architecture

| Component | Technology |
|-----------|-----------|
| API | FastAPI — 171 REST endpoints, ABAC-scoped, rate-limited |
| CLI | Click + Rich — 686 leaf commands across 73 modules |
| Database | SQLAlchemy 2.0, PostgreSQL (prod) / SQLite (dev), 47 models |
| Data Lake | DuckDB + Parquet — 23 modules across 3 zones |
| Policy Engine | OPA/Rego — 670 policies |
| Infrastructure | Terraform — 12 IaC modules (AWS, Azure, GCP) |
| AI | Pluggable — Anthropic, OpenAI, Gemini, Ollama |
| Security | JWT + RBAC + ABAC + bcrypt + GDPR workflows |

Python 3.12+. `make demo` for one-command setup. Production-ready with PostgreSQL, Redis, and OPA.

## Who It's For

| Role | Value |
|------|-------|
| **Compliance teams** | Run pipelines, review results, manage POA&Ms, prepare for audits with pre-built evidence binders |
| **Security engineers** | Configure connectors, write custom assertions, define OPA policies, integrate with existing tooling |
| **CISOs / Risk managers** | Track posture trends, quantify risk in financial terms, monitor compliance drift, produce board-ready reports |
| **Auditors** | Verify the hash-chained trail independently, consume OSCAL exports, access the audit evidence binder |

## Quick Start

```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
make demo
```

API at localhost:8000/docs. 165 connectors, ~5,475 findings, 373,000+ control results seeded automatically.
