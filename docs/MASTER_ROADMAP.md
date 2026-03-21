# Warlock Master Enhancement Roadmap

Generated 2026-03-19 from 9 specialist agent analyses + Senior GRC Assessment (2026-03-20) + Product Vision (2026-03-21).
**Total items: 148** | **Done: 72** | **Remaining: 76**

---

## Completed (69 items)

<details>
<summary>P0 — 22/22 done</summary>

- [x] 1. Parallel connector collection — `ThreadPoolExecutor` in `collect_all()` (S)
- [x] 2. Batch OPA evaluation — 592 HTTP calls → 7 per framework (M)
- [x] 3. Fix double-normalization in OPA evaluator (S)
- [x] 4. Framework YAML `@lru_cache` — stop re-parsing disk every run (S)
- [x] 5. Coverage summary caching — hottest endpoint does full table scan (S)
- [x] 6. Parallel AI calls for SSP export — `asyncio.gather` (M)
- [x] 7. Prometheus `/metrics` endpoint (S)
- [x] 8. Run-ID log correlation (S)
- [x] 9. JSON → JSONB migration for PostgreSQL (S)
- [x] 10. Materialized views — coverage, posture, framework rollups (M)
- [x] 11. Composite index on `control_results(framework, status, assessed_at)` (S)
- [x] 12. GDPR assertion bindings + Rego policies (L)
- [x] 13. HIPAA assertion bindings (S)
- [x] 14. FedRAMP SSP template + CRM + CIS generation (XL)
- [x] 15. SOC 2 Type II historical evidence retention (L)
- [x] 16. ISO 27001 Statement of Applicability export (M)
- [x] 17. API documentation — mount FastAPI `/docs` (S)
- [x] 18. Deployment guide (L)
- [x] 19. CONTRIBUTING.md (S)
- [x] 20. Evidence chain of custody — hash verification (M)
- [x] 21. MFA/TOTP support (L)
- [x] 22. Continuous control monitoring — event-driven reassessment (L)

</details>

<details>
<summary>P1 — 50/55 done</summary>

- [x] 23–60, 123. All original P1 items (42 done)
- [x] 126. Encrypt MFA TOTP secrets with FieldEncryptor (S) — done 2026-03-21
- [x] 127. Signed MFA challenge tokens (S) — done 2026-03-21
- [x] 128. Complete ABAC scope coverage on risk/policy/simulation endpoints (M) — done 2026-03-21
- [x] 129. Split app.py into 9 FastAPI domain routers (L) — done 2026-03-21
- [x] 130. Split cli.py into 8 Click sub-modules (M) — done 2026-03-21
- [x] 131. API test suite — 105 HTTP-level tests covering auth, ABAC, pagination, all routers (L) — done 2026-03-21
- [x] 132. Move in-memory state to shared cache (MemoryCache/RedisCache abstraction) (M) — done 2026-03-21
- [x] 133. Assertion expansion 25 → 101 across 14 control families (XL) — done 2026-03-21

</details>

---

## P1 — Remaining (0 items)

All P1 items complete.

---

## P2 — Next Quarter (56 items)

Differentiation. Makes Warlock unique.

### Data Governance & Discovery (7 items — new)

| # | What | Effort | Why |
|---|------|--------|-----|
| 136 | **Databricks Unity Catalog connector** — table/column access controls, audit logs, data lineage, ML model governance via REST API. SourceType: DATA_GOVERNANCE | L | Data governance + ML model inventory in one source |
| 137 | **DataHub connector** — open source (Apache 2.0) metadata platform. Pull data catalog, column-level lineage, quality assertions, governance policies via GraphQL. SourceType: DATA_GOVERNANCE | L | Free data catalog — instant data silo discovery, PCI CDE scoping, HIPAA PHI tracking, GDPR Article 30 |
| 138 | **Atlan connector** — enterprise data catalog. Pull metadata, lineage, classification, governance policies via REST + GraphQL. SourceType: DATA_GOVERNANCE | M | Enterprise data governance catalog |
| 139 | **Active data silo discovery** — enhance AWS/Azure/GCP connectors to enumerate all data stores (S3, RDS, DynamoDB, Redshift, Glue, Storage Accounts, SQL DBs, Cosmos DB, BigQuery, Cloud SQL, GCS). Auto-create DataSilo records for unclassified stores | L | Orgs don't know where all their data lives — automated discovery is table stakes for GDPR/HIPAA/PCI |
| 140 | **Data classification & sensitivity scoring** — PII/PHI/PCI pattern detection on discovered data stores. Column-level sensitivity tagging. Feed results into data silo model | L | Classification without detection is just a spreadsheet |
| 141 | **Data lineage tracking** — ETL pipeline tracking (Airflow, dbt, Fivetran), API call graphs, DataHub/Atlan integration for existing lineage | M | Required for GDPR DPIAs, PCI CDE scoping, breach impact analysis |
| 142 | **Data silo drift detection** — alert when new data stores appear that aren't classified. Compare current cloud inventory against known silos. EventBus integration for real-time alerts | M | Unknown data stores are unprotected data stores |

### AI Governance & Shadow AI (5 items — new)

| # | What | Effort | Why |
|---|------|--------|-----|
| 143 | **Shadow AI detection assertions** — analyze Zscaler/Netskope/proxy connector data for unauthorized calls to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com. Map to ISO 42001 and EU AI Act controls | M | Growing regulatory requirement; orgs can't govern AI they don't know about |
| 144 | **AI model inventory connectors** — SageMaker Model Registry, Azure ML, Vertex AI Model Registry, HuggingFace Hub. Track deployed models, versions, training data provenance | L | ISO 42001 requires AI asset inventory; EU AI Act requires high-risk AI registry |
| 145 | **AI policy enforcement assertions** — approved model registry checks, data classification gates (PII/PHI must not be sent to external AI APIs), human oversight requirements for high-risk decisions | M | Maps directly to existing EU AI Act (33 controls) and ISO 42001 (39 controls) frameworks |
| 146 | **Cloud AI billing anomaly detection** — monitor cloud billing APIs for unexpected AI API charges as shadow AI signal | S | Low-effort shadow AI indicator from data already in cloud connectors |
| 147 | **AI incident tracking model** — AI-specific incident type for bias events, hallucination reports, data leakage via AI, model performance degradation | M | EU AI Act Article 62 requires serious incident reporting for high-risk AI |

### GRC Platform Connectors (5 items — new)

| # | What | Effort | Why |
|---|------|--------|-----|
| 148 | **Vanta connector** (inbound) — pull test results, evidence, monitor status via REST API. SourceType: GRC | M | Aggregation layer for orgs already running Vanta |
| 149 | **Drata connector** (inbound) — pull controls, evidence, personnel compliance via REST API. SourceType: GRC | M | Aggregation layer for orgs already running Drata |
| 150 | **AuditBoard connector** (inbound) — pull audit findings, control testing results, SOX workflows via REST API. SourceType: GRC | M | Enterprise GRC aggregation |
| 151 | **Conveyor connector** (inbound) — pull security review status, questionnaire responses via REST API. SourceType: GRC | S | Trust center / security review aggregation |
| 152 | **Outbound GRC export API** — export Warlock data in Vanta/Drata/AuditBoard formats so Warlock can be the compliance engine behind any GRC frontend | L | "Warlock powers them" play — the more interesting direction |

### Privacy Operations (1 item — new)

| # | What | Effort | Why |
|---|------|--------|-----|
| 153 | **Transcend connector** — pull privacy requests (DSR), data maps, consent records via REST API. Feed into GDPR workflows and data silo inventory. SourceType: GRC | M | Privacy operations automation — DSR compliance, consent management |

### AI (5 items)

| # | What | Effort |
|---|------|--------|
| 61 | Natural language compliance queries | L |
| 62 | Automated evidence validation | M |
| 63 | Predictive drift | M |
| 64 | Remediation copilot | M |
| 65 | Compliance-aware code review | L |

### Architecture (8 items)

| # | What | Effort |
|---|------|--------|
| 66 | Multi-tenancy | XL |
| 67 | WebSocket real-time dashboard | M |
| 68 | Plugin architecture for connectors/normalizers | L |
| 69 | Compliance-as-Code SDK for CI/CD | L |
| 70 | Table partitioning for 6 high-growth tables | M |
| 71 | TimescaleDB for posture snapshots | L |
| 72 | Full-text search via PostgreSQL tsvector | M |
| 73 | Archive strategy — hot/warm/cold with legal hold awareness | M |

### Terraform (3 items)

| # | What | Effort |
|---|------|--------|
| 74 | Multi-cloud parity — AWS 12, Azure 4, GCP 4 modules | L |
| 75 | Terragrunt wrapper for multi-account deployment | L |
| 76 | Private module registry | M |

### Compliance Depth (6 items)

| # | What | Effort |
|---|------|--------|
| 77 | FedRAMP ConMon tooling | L |
| 78 | SOC 2 points of focus (200+) | M |
| 79 | Attestation workflow — SOC 2/ISO artifact generation | M |
| 80 | CIS Benchmark mappings for AWS/Azure/GCP | M |
| 81 | NIST 800-53 enhancement-level coverage (1,034 gaps) | XL |
| 82 | Reverse crosswalks — HIPAA→UCF, GDPR→UCF | M |

### Risk (5 items)

| # | What | Effort |
|---|------|--------|
| 83 | Bayesian network risk models | L |
| 84 | Business Impact Analysis module | XL |
| 85 | Insider threat scoring from IAM/EDR behavioral data | M |
| 86 | Control effectiveness decay modeling | M |
| 87 | Monte Carlo ProcessPoolExecutor for portfolio parallelism | M |

### Trust Portal (3 items)

| # | What | Effort |
|---|------|--------|
| 88 | Self-service evidence requests | M |
| 89 | NDA-gated tiered access levels | M |
| 90 | Incident communication status page | M |

### Privacy (3 items)

| # | What | Effort |
|---|------|--------|
| 91 | Consent management integration (OneTrust connector) | M |
| 92 | Cross-border transfer tracking | M |
| 93 | Right to data portability — standardized export format | S |

### Risk Management (4 items)

| # | What | Effort |
|---|------|--------|
| 94 | FAIR taxonomy full decomposition | M |
| 95 | Loss magnitude categories — productivity/response/fines/reputation | M |
| 96 | Threat modeling integration — STRIDE/MITRE ATT&CK | L |
| 97 | TPRM lifecycle — onboarding/assessment/monitoring/offboarding | L |

### Performance (2 items)

| # | What | Effort |
|---|------|--------|
| 98 | Cold start optimization — remove `init_db()` from scheduler tick | S |
| 99 | Iterator-based OPA data assembly — eliminate second findings copy | M |

### Privacy Engineering (4 items)

| # | What | Effort | Notes |
|---|------|--------|-------|
| 119 | Presidio PII detector assessor | M | Blocked: Presidio incompatible with Python 3.14 |
| 120 | detect-secrets pipeline assessor | S | |
| 121 | scrubadub export sanitizer | S | |
| 122 | pii-codex regulatory classification | S | Blocked: depends on Presidio |

### Export & Reporting (2 items)

| # | What | Effort |
|---|------|--------|
| 124 | Human-readable SSP export — Markdown/PDF with narrative statements | L |
| 125 | Audit package builder CLI — bundles SSP + AR + POA&M + evidence binder | M |

### Supply Chain & Pentest (2 items)

| # | What | Effort |
|---|------|--------|
| 134 | SBOM / supply chain compliance — CycloneDX/SPDX, VEX, license compliance | L |
| 135 | Pentest lifecycle management — engagement tracking, finding dedup, vuln SLA | L |

---

## P3 — Roadmap (18 items)

When the product has traction.

### Platform (6 items)

| # | What | Effort |
|---|------|--------|
| 100 | GraphQL API alongside REST | L |
| 101 | GPU-accelerated Monte Carlo via cupy | L |
| 102 | Lambda SnapStart for serverless | L |
| 103 | Embedded OPA — eliminate sidecar HTTP | L |
| 104 | Public Terraform Registry publication | XL |
| 105 | Streaming SSP response via `StreamingResponse` | M |

### Frameworks (4 items)

| # | What | Effort |
|---|------|--------|
| 106 | ITAR framework | L |
| 107 | CJIS framework | M |
| 108 | StateRAMP framework | M |
| 109 | NIST AI RMF | M |

### Risk Management (5 items)

| # | What | Effort |
|---|------|--------|
| 110 | Nth-party vendor risk visibility | M |
| 111 | SLA compliance tracking per vendor | S |
| 112 | Vendor incident notification workflow | M |
| 113 | DR testing tracking | M |
| 114 | KRI (Key Risk Indicators) dashboard | M |

### Misc (3 items)

| # | What | Effort |
|---|------|--------|
| 115 | Risk register — strategic/operational/financial beyond POA&Ms | M |
| 116 | Compliance deadline forecasting | M |
| 118 | Privacy by design CI enforcement | M |

---

## Coverage Verification

| Source | Total Findings | Covered in Roadmap | Gap |
|---|---|---|---|
| GRC Engineer | 20 enhancements | 20/20 | 0 |
| Architect | 18 findings | 18/18 | 0 |
| Security | 36 findings | 36/36 | 0 |
| Database | 9 findings | 9/9 | 0 |
| Terraform | 7 findings | 7/7 | 0 |
| Compliance | 23 findings | 23/23 | 0 |
| Performance | 34 findings | 34/34 | 0 |
| Documentation | 7 categories | 7/7 | 0 |
| Risk Manager | 28 findings | 28/28 | 0 |
| Senior GRC Assessment (2026-03-20) | 10 new findings | 10/10 | 0 |
| Product Vision (2026-03-21) | 20 new items | 20/20 | 0 |
| **Total** | **212 findings** | **212/212** | **0 gaps** |

---

## Effort Summary — Remaining Only

| Priority | Items | S | M | L | XL |
|---|---|---|---|---|---|
| P1 | 0 (all done) | — | — | — | — |
| P2 | 56 | 6 | 28 | 18 | 4 |
| P3 | 18 | 1 | 9 | 7 | 1 |
| **Remaining** | **74** | **7** | **37** | **25** | **5** |
