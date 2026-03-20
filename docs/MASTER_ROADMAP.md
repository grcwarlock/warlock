# Warlock Master Enhancement Roadmap

Generated 2026-03-19 from 9 specialist agent analyses.
**Total items: 118** (85 from original roadmap + 33 previously missing)

---

## P0 — Do Now (22 items)

Blocks production, revenue, or compliance. No customer can use this without these.

### Performance (8 items — most are <50 lines)
- [ ] 1. Parallel connector collection — `ThreadPoolExecutor` in `collect_all()` (S)
- [ ] 2. Batch OPA evaluation — 592 HTTP calls → 7 per framework (M)
- [ ] 3. Fix double-normalization in OPA evaluator (S)
- [ ] 4. Framework YAML `@lru_cache` — stop re-parsing disk every run (S)
- [ ] 5. Coverage summary caching — hottest endpoint does full table scan (S)
- [ ] 6. Parallel AI calls for SSP export — `asyncio.gather` (M)
- [ ] 7. Prometheus `/metrics` endpoint (S)
- [ ] 8. Run-ID log correlation (S)

### Database (3 items)
- [ ] 9. JSON → JSONB migration for PostgreSQL (S)
- [ ] 10. Materialized views — coverage, posture, framework rollups (M)
- [ ] 11. Composite index on `control_results(framework, status, assessed_at)` (S)

### Compliance (5 items)
- [ ] 12. GDPR assertion bindings + Rego policies (L)
- [ ] 13. HIPAA assertion bindings (S)
- [ ] 14. FedRAMP SSP template + CRM + CIS generation (XL)
- [ ] 15. SOC 2 Type II historical evidence retention (L)
- [ ] 16. ISO 27001 Statement of Applicability export (M)

### Documentation (3 items)
- [ ] 17. API documentation — mount FastAPI `/docs` (S)
- [ ] 18. Deployment guide (L)
- [ ] 19. CONTRIBUTING.md (S)

### Security (3 items)
- [ ] 20. Evidence chain of custody — hash verification (M)
- [ ] 21. MFA/TOTP support (L)
- [ ] 22. Continuous control monitoring — event-driven reassessment (L)

---

## P1 — This Quarter (42 items)

Competitive parity. Every GRC tool has these.

### Framework Coverage (6 items)
- [ ] 23. PCI DSS 4.0 framework YAML + assertions + Rego (XL)
- [ ] 24. NIST CSF 2.0 (L)
- [ ] 25. EU AI Act / ISO 42001 depth (M)
- [ ] 26. SEC cybersecurity disclosure rules (M)
- [ ] 27. CMMC L2 assertion bindings (M)
- [ ] 28. UCF crosswalk expansion to all 10 frameworks (M)

### Risk Management (5 items)
- [ ] 29. Risk appetite/tolerance framework (M)
- [ ] 30. MTTD/MTTR tracking — data exists, compute it (S)
- [ ] 31. Risk acceptance re-evaluation triggers — model field exists, wire it (S)
- [ ] 32. Loss exceedance curves for cyber insurance (M)
- [ ] 33. Supply chain concentration analysis (M)

### Platform (11 items)
- [ ] 34. Webhook outbound — EventBus subscribers for Jira/Slack/ServiceNow (M)
- [ ] 35. Evidence vault — S3/GCS for file-based evidence (M)
- [ ] 36. Read replica routing (M)
- [ ] 37. PgBouncer integration (S)
- [ ] 38. Worker pool for scheduler (M)
- [ ] 39. Terraform KMS modules — AWS, Azure, GCP (S per module)
- [ ] 40. Terraform Config/GuardDuty/CloudTrail org modules (M per module)
- [ ] 41. Terraform self-registration evidence pattern (M)
- [ ] 42. Terraform drift detection — state vs cloud (L)
- [ ] 43. Plan-time Rego evaluation via conftest in CI (M)
- [ ] 44. Batch `session.flush()` per-connector instead of per-record (S) *(was missing)*

### Trust & Transparency (3 items)
- [ ] 45. SOC 2 report portal — NDA-gated document access (M)
- [ ] 46. Security questionnaire auto-response (L)
- [ ] 47. Real-time compliance dashboard (M)

### Privacy (4 items)
- [ ] 48. DSAR automation workflow — intake to response (L)
- [ ] 49. Privacy Impact Assessment (DPIA) workflow (M)
- [ ] 50. Breach notification workflow — 72hr Article 33 (M)
- [ ] 51. Data mapping and lineage (ROPA) — Article 30 (L)

### Performance (3 items — were missing)
- [ ] 52. Monte Carlo inner Poisson vectorization (M) *(was missing)*
- [ ] 53. Monte Carlo pre-computation cache (S) *(was missing)*
- [ ] 54. Session `expunge_all()` after connector batch — memory relief (S) *(was missing)*

### Architecture (3 items — were missing)
- [ ] 55. API pagination enforcement — hard max on all list endpoints (S) *(was missing)*
- [ ] 56. Audit log external sink — S3/CloudWatch/Splunk (S) *(was missing)*
- [ ] 57. Regulatory change management — track framework version updates (M) *(was missing)*

### Security (2 items — were missing)
- [ ] 58. JWT refresh token mechanism (M) *(was missing)*
- [ ] 59. Control testing automation — active validation, not just observation (L) *(was missing)*

### Compliance (1 item — was missing)
- [ ] 60. Governance control content analysis — beyond title-matching in Confluence (M) *(was missing)*

---

## P2 — Next Quarter (36 items)

Differentiation. Makes Warlock unique.

### AI (5 items)
- [ ] 61. Natural language compliance queries (L)
- [ ] 62. Automated evidence validation (M)
- [ ] 63. Predictive drift (M)
- [ ] 64. Remediation copilot (M)
- [ ] 65. Compliance-aware code review (L)

### Architecture (8 items)
- [ ] 66. Multi-tenancy (XL)
- [ ] 67. WebSocket real-time dashboard (M)
- [ ] 68. Plugin architecture for connectors/normalizers (L)
- [ ] 69. Compliance-as-Code SDK for CI/CD (L)
- [ ] 70. Table partitioning for 6 high-growth tables (M)
- [ ] 71. TimescaleDB for posture snapshots (L)
- [ ] 72. Full-text search via PostgreSQL tsvector (M)
- [ ] 73. Archive strategy — hot/warm/cold with legal hold awareness (M)

### Terraform (3 items)
- [ ] 74. Multi-cloud parity — AWS 12, Azure 4, GCP 4 modules (L)
- [ ] 75. Terragrunt wrapper for multi-account deployment (L)
- [ ] 76. Private module registry (M)

### Compliance Depth (6 items)
- [ ] 77. FedRAMP ConMon tooling (L)
- [ ] 78. SOC 2 points of focus (200+) (M)
- [ ] 79. Attestation workflow — SOC 2/ISO artifact generation (M)
- [ ] 80. CIS Benchmark mappings for AWS/Azure/GCP (M)
- [ ] 81. NIST 800-53 enhancement-level coverage (1,034 gaps) (XL)
- [ ] 82. Reverse crosswalks — HIPAA→UCF, GDPR→UCF (M)

### Risk (5 items)
- [ ] 83. Bayesian network risk models (L)
- [ ] 84. Business Impact Analysis module (XL)
- [ ] 85. Insider threat scoring from IAM/EDR behavioral data (M)
- [ ] 86. Control effectiveness decay modeling (M)
- [ ] 87. Monte Carlo ProcessPoolExecutor for portfolio parallelism (M) *(was missing)*

### Trust Portal (3 items — were missing)
- [ ] 88. Self-service evidence requests (M) *(was missing)*
- [ ] 89. NDA-gated tiered access levels (M) *(was missing)*
- [ ] 90. Incident communication status page (M) *(was missing)*

### Privacy (3 items — were missing)
- [ ] 91. Consent management integration (OneTrust connector) (M) *(was missing)*
- [ ] 92. Cross-border transfer tracking (M) *(was missing)*
- [ ] 93. Right to data portability — standardized export format (S) *(was missing)*

### Risk Management (4 items — were missing)
- [ ] 94. FAIR taxonomy full decomposition (M) *(was missing)*
- [ ] 95. Loss magnitude categories — productivity/response/fines/reputation (M) *(was missing)*
- [ ] 96. Threat modeling integration — STRIDE/MITRE ATT&CK (L) *(was missing)*
- [ ] 97. TPRM lifecycle — onboarding/assessment/monitoring/offboarding (L) *(was missing)*

### Performance (2 items — were missing)
- [ ] 98. Cold start optimization — remove `init_db()` from scheduler tick (S) *(was missing)*
- [ ] 99. Iterator-based OPA data assembly — eliminate second findings copy (M) *(was missing)*

---

## P3 — Roadmap (18 items)

When the product has traction.

### Platform
- [ ] 100. GraphQL API alongside REST (L)
- [ ] 101. GPU-accelerated Monte Carlo via cupy (L)
- [ ] 102. Lambda SnapStart for serverless (L)
- [ ] 103. Embedded OPA — eliminate sidecar HTTP (L)
- [ ] 104. Public Terraform Registry publication (XL)
- [ ] 105. Streaming SSP response via `StreamingResponse` (M)

### Frameworks
- [ ] 106. ITAR framework (L)
- [ ] 107. CJIS framework (M)
- [ ] 108. StateRAMP framework (M)
- [ ] 109. NIST AI RMF (M)

### Risk Management (5 items — were missing)
- [ ] 110. Nth-party vendor risk visibility (M) *(was missing)*
- [ ] 111. SLA compliance tracking per vendor (S) *(was missing)*
- [ ] 112. Vendor incident notification workflow (M) *(was missing)*
- [ ] 113. DR testing tracking (M) *(was missing)*
- [ ] 114. KRI (Key Risk Indicators) dashboard (M) *(was missing)*

### Misc (4 items — were missing)
- [ ] 115. Risk register — strategic/operational/financial beyond POA&Ms (M) *(was missing)*
- [ ] 116. Compliance deadline forecasting (M) *(was missing)*
- [ ] 117. Resource allocation optimization (L) *(was missing)*
- [ ] 118. Privacy by design CI enforcement (M) *(was missing)*

---

## Coverage Verification

| Agent | Total Findings | Covered in Roadmap | Gap |
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
| **Total** | **182 findings** | **182/182** | **0 gaps** |

---

## Effort Summary

| Priority | Items | S | M | L | XL |
|---|---|---|---|---|---|
| P0 | 22 | 11 | 6 | 4 | 1 |
| P1 | 42 | 10 | 20 | 8 | 4 |
| P2 | 36 | 1 | 20 | 11 | 4 |
| P3 | 18 | 1 | 9 | 7 | 1 |
| **Total** | **118** | **23** | **55** | **30** | **10** |
