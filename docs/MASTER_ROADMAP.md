# Warlock Master Enhancement Roadmap

Generated 2026-03-19 from 9 specialist agent analyses + Senior GRC Assessment (2026-03-20).
**Total items: 128** | **Done: 64** | **Remaining: 64**

---

## Completed (64 items)

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
<summary>P1 — 42/50 done</summary>

- [x] 23. PCI DSS 4.0 framework YAML + assertions + Rego (XL)
- [x] 24. NIST CSF 2.0 (L)
- [x] 25. EU AI Act / ISO 42001 depth (M)
- [x] 26. SEC cybersecurity disclosure rules (M)
- [x] 27. CMMC L2 assertion bindings (M)
- [x] 28. UCF crosswalk expansion to all 10 frameworks (M)
- [x] 29. Risk appetite/tolerance framework (M)
- [x] 30. MTTD/MTTR tracking (S)
- [x] 31. Risk acceptance re-evaluation triggers (S)
- [x] 32. Loss exceedance curves for cyber insurance (M)
- [x] 33. Supply chain concentration analysis (M)
- [x] 34. Webhook outbound — EventBus subscribers for Jira/Slack/ServiceNow/PagerDuty (M)
- [x] 35. Evidence vault — S3/GCS for file-based evidence (M)
- [x] 36. Read replica routing (M)
- [x] 37. PgBouncer integration (S)
- [x] 38. Worker pool for scheduler (M)
- [x] 39. Terraform KMS modules — AWS, Azure, GCP (S per module)
- [x] 40. Terraform Config/GuardDuty/CloudTrail org modules (M per module)
- [x] 41. Terraform self-registration evidence pattern (M)
- [x] 42. Terraform drift detection — state vs cloud (L)
- [x] 43. Plan-time Rego evaluation via conftest in CI (M)
- [x] 44. Batch `session.flush()` per-connector instead of per-record (S)
- [x] 45. SOC 2 report portal — NDA-gated document access (M)
- [x] 46. Security questionnaire auto-response (L)
- [x] 47. Real-time compliance dashboard (M)
- [x] 52. Monte Carlo inner Poisson vectorization (M)
- [x] 53. Monte Carlo pre-computation cache (S)
- [x] 54. Session `expunge_all()` after connector batch (S)
- [x] 55. API pagination enforcement (S)
- [x] 56. Audit log external sink — S3/CloudWatch/Splunk (S)
- [x] 57. Regulatory change management (M)
- [x] 58. JWT refresh token mechanism (M)
- [x] 59. Control testing automation (L)
- [x] 60. Governance control content analysis (M)
- [x] 123. Change `ai_enabled` default to `False` (S)

</details>

---

## P1 — Remaining (8 items)

Security and structural fixes. Do before anything else.

### Security — Critical (3 items)

| # | What | Effort | Source |
|---|------|--------|--------|
| 126 | **Encrypt MFA TOTP secrets with FieldEncryptor** — DB compromise = full MFA bypass without this | S | Assessment C1/H5 |
| 127 | **Signed MFA challenge tokens** — replace raw user_id in MFA flow to prevent brute-force | S | Assessment H1 |
| 128 | **Complete ABAC scope coverage on all API endpoints** — partial fix exists, many endpoints still unscoped | M | Assessment H2 |

### Architecture — Structural (3 items)

| # | What | Effort | Source |
|---|------|--------|--------|
| 129 | **Split app.py into FastAPI routers** — 5,400 lines, unreviewable, missed auth = bypass | L | Assessment A1 |
| 130 | **Split cli.py into Click sub-command modules** — 3,600 lines in one file | M | Assessment A2 |
| 131 | **API test suite** — 139 routes with zero HTTP-level tests covering auth, ABAC, pagination | L | Assessment A7 |

### Platform — Scalability (2 items)

| # | What | Effort | Source |
|---|------|--------|--------|
| 132 | **Move in-memory state to shared store** — coverage cache, alert config, conversation manager, rate limiter all per-process; breaks multi-worker | M | Assessment A6 |
| 133 | **Assertion expansion 25 → 100+** — shifts deterministic coverage from 1.3% to ~30%; each assertion ~30 LOC | XL | Assessment A4 |

---

## P2 — Next Quarter (37 items)

Differentiation. Makes Warlock unique.

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

| # | What | Effort | Source |
|---|------|--------|--------|
| 134 | SBOM / supply chain compliance — CycloneDX/SPDX, VEX, license compliance | L | Assessment |
| 135 | Pentest lifecycle management — engagement tracking, finding dedup, vuln SLA | L | Assessment |

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
| **Total** | **192 findings** | **192/192** | **0 gaps** |

---

## Effort Summary — Remaining Only

| Priority | Items | S | M | L | XL |
|---|---|---|---|---|---|
| P1 | 8 | 2 | 3 | 2 | 1 |
| P2 | 37 | 4 | 20 | 11 | 2 |
| P3 | 18 | 1 | 9 | 7 | 1 |
| **Remaining** | **63** | **7** | **32** | **20** | **4** |
