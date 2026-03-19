# Warlock v2 — Architectural Gap Analysis & Roadmap

**Date:** 2026-03-18
**Scope:** Storage, AI Reasoning, Signal/Dashboard, Audit Export, and remaining tool coverage gaps

---

## Platform State at Time of Analysis

| Metric | Count |
|---|---|
| Connectors | 36 |
| Normalizers | 37 |
| Assertions | 25 |
| Assertion bindings | 99 |
| Frameworks | 6 (NIST 800-53, SOC 2, ISO 27001, ISO 27701, ISO 42001, UCF) |
| Total controls | 1,564 |
| Explicit mapping rules | 2,685 |
| Resource mapping rules | 2,222 |
| Crosswalk edges | 1,816 |
| Tests | 21/21 passing |

---

## 1. Storage & Normalization Layer

### What Exists

- 5-table schema: `ConnectorRun → RawEvent → Finding → ControlMapping → ControlResult`
- SHA256 hashes on both `RawEvent` and `Finding` for integrity
- Full lineage chain: every result traces back to raw source data
- SQLite for dev, Postgres via `WLK_DATABASE_URL`
- Cross-framework querying works — same finding can map to NIST AC-2, SOC2 CC6.1, ISO A.5.16, and UCF-IAM-1 simultaneously

### Gaps

| Gap | Impact | Priority |
|---|---|---|
| **No immutable audit trail** | ConnectorRun/RawEvent rows can be updated/deleted. No append-only table, no write-ahead log, no blockchain-style hash chaining. An auditor can't prove evidence wasn't tampered with post-collection. | P0 |
| **No trusted timestamping** | `_utcnow()` uses local system clock. No RFC 3161 TSA (Timestamp Authority) integration. Evidence timestamps are self-asserted, not independently verifiable. | P1 |
| **No data retention policies** | No TTL, no archival, no purge schedules. SOC 2 Type II needs 12 months of evidence. Some financial regs need 7 years. No mechanism to enforce or configure this. | P1 |
| **No evidence packaging model** | Raw JSON blobs in `raw_data`. No concept of an "evidence artifact" — a discrete, signable, exportable unit that an auditor can independently verify. The OSCAL export reconstructs from DB rows, but there's no pre-packaged evidence bundle per control per audit period. | P1 |
| **No point-in-time snapshots** | Can query by `assessed_at` range, but no snapshot table. Can't answer "what was AC-2 posture on March 1st?" without scanning all historical rows. Need a `PostureSnapshot` table with periodic roll-ups. | P2 |
| **No evidence sufficiency model** | A control might have 1 finding or 100. No concept of "enough evidence" — no minimum evidence threshold per control, no gap detection for controls with zero evidence sources. | P2 |
| **SQLite JSON limitations** | `SQLiteJSON` works for dev but doesn't support JSON path queries. Postgres `JSONB` with `GIN` indexes needed for efficient filtering on `detail` fields. No Alembic migrations set up for schema evolution. | P2 |

### Recommended Additions

1. **`EvidenceArtifact` table** — immutable, append-only, with hash chain linking each row to its predecessor
2. **`PostureSnapshot` table** — periodic control-level rollups (daily/weekly)
3. **`RetentionPolicy` config** — per-framework retention periods with automated archival
4. **Alembic migration setup** for schema evolution

---

## 2. AI Reasoning Layer

### What Exists

- **Tier 1:** 25 deterministic assertions with 99 control bindings across 6 frameworks
- **Tier 2:** AI reasoning via 4 LLM providers (Anthropic, OpenAI, Gemini, Ollama) — single-finding evaluation
- **Tier 3:** Anomaly detection (drift, volume, access patterns, statistical) with sklearn + pure-Python fallbacks
- **Tier 4:** RAG semantic control matching (TF-IDF/OpenAI embeddings + vector stores)
- **AI Narrator:** Framework-aware narrative generation for SSP/POA&M/SoA documents

### Gaps

| Gap | What It Would Do | Priority |
|---|---|---|
| **Natural language policy interpretation** | Ingest customer's actual policy PDFs (InfoSec Policy, Acceptable Use Policy, BCP plan) and verify technical controls satisfy stated commitments. Currently assesses against framework controls but can't validate against customer's own policies. Needs: PDF ingestion → RAG index → policy-vs-evidence reasoning. | P1 |
| **Evidence sufficiency scoring** | For each control, score whether collected evidence is audit-adequate. A control with 50 IAM findings has plenty; a control with 1 stale finding from 6 months ago does not. Needs: per-control evidence freshness, volume, diversity, and coverage metrics → sufficiency score (0-100). | P1 |
| **Compensating control reasoning** | When AC-2 fails, identify that AC-6 + IA-2 together compensate. Needs: control dependency graph + AI reasoning about compensating effectiveness. This is how real auditors work — they accept compensating controls for findings. | P1 |
| **Risk quantification (FAIR model)** | Translate control posture → quantitative risk. Loss Event Frequency × Loss Magnitude = Annual Loss Expectancy. Currently have pass/fail and severity, but no dollar-value risk estimates. Needs: FAIR taxonomy mapping + industry loss data + Monte Carlo simulation. | P2 |
| **Cross-framework conflict detection** | ISO 27701 A.7.4.7 (PII disposal/minimization) can conflict with AU-11 (audit record retention). Flag where overlapping requirements create tension and recommend resolution strategies. Needs: framework-aware constraint graph + conflict detection rules. | P2 |
| **Continuous posture scoring** | Beyond point-in-time pass/fail — a rolling posture score per control that trends over time, with leading indicators predicting failure. Anomaly detector has primitives but no posture score model or trend storage. | P2 |
| **Multi-tenant policy evaluation** | Different business units may have different risk appetites and control implementations. No concept of "system boundary" or "authorization boundary" — everything assessed as one flat namespace. | P2 |

---

## 3. Signal & Dashboard Layer

### What Exists

- CLI commands: `results`, `coverage`, `findings` with Rich table output
- Event bus publishing: `raw_event.created`, `finding.normalized`, `finding.mapped`, `control.assessed`
- Queue backends (Redis/Kafka/SQS) for production event streaming
- Basic compliance rate calculation in `coverage` command

### Gaps

| Gap | What It Would Do | Priority |
|---|---|---|
| **REST API** | No FastAPI/Django layer. Everything is CLI-only. Can't build a dashboard, can't integrate with other tools, can't serve a UI. Single biggest missing piece for productization. | P0 |
| **Authentication / RBAC** | No users, no roles, no permissions. GRC data is sensitive — needs at minimum: admin, auditor (read-only), system owner (scoped to their boundary). | P0 |
| **Control-level rollup/aggregation** | AC-2 might have 200 findings across 10 sources. No aggregated "AC-2 status" — just individual ControlResult rows. Needs: per-control posture roll-up logic (worst-case, majority-vote, weighted). | P1 |
| **Framework-specific risk scoring** | A critical finding in NIST SI-2 maps to medium in SOC 2 CC9.1. Different frameworks weight the same evidence differently. No per-framework severity weighting. | P1 |
| **Blast radius analysis** | When Okta goes non-compliant, which controls across which frameworks are affected? AC-2, IA-2, CC6.1, A.5.16, UCF-IAM-1... The crosswalk graph has this data but no "impact cascade" query. | P1 |
| **Alert routing / notifications** | No webhook, Slack, PagerDuty, email integration for posture degradation. Event bus can publish but nothing subscribes to send external notifications. | P1 |
| **Executive vs. practitioner vs. auditor views** | No view layer differentiation. Executive needs risk posture heatmap; practitioner needs control detail with remediation; auditor needs evidence packages scoped to engagement. | P2 |

---

## 4. Audit Export Layer

### What Exists

- OSCAL 1.1.2 export: Assessment Results, SSP, POA&M
- AI Narrator for framework-aware narrative generation
- JSON file output via CLI (`warlock oscal --format ar|ssp|poam`)

### Gaps

| Gap | What It Would Do | Priority |
|---|---|---|
| **Temporal evidence packaging** | Can't answer "give me all evidence for SOC 2 Type II covering Jan 1–Dec 31 2025." OSCAL export dumps current state, not bounded audit periods. Needs: audit period scoping (start/end dates) on all queries. | P1 |
| **SOC 2 Type II report structure** | SOC 2 auditors expect: management assertion, service description, control descriptions, test procedures, test results, exceptions. OSCAL SSP doesn't produce this. Needs: SOC 2-specific report template. | P1 |
| **ISO evidence binder format** | ISO auditors want evidence organized by Annex A clause: SoA entry, implementation evidence, effectiveness evidence. Different from OSCAL. | P1 |
| **Evidence sampling support** | Auditors don't review all evidence — they sample. No mechanism for auditor to select a sample, mark items reviewed, document testing procedures. | P2 |
| **Exception / management response workflow** | No workflow for management response to auditor exceptions, remediation plans, verification. POA&M captures findings but no lifecycle management. | P2 |
| **PDF report generation** | Auditors want PDFs, not JSON. Need report rendering layer producing formatted PDFs from OSCAL data. | P2 |
| **OSCAL schema validation** | Produce OSCAL JSON but never validate against NIST OSCAL schemas. Should validate output before export. | P2 |

---

## 5. Additional Missing Tool Integrations

### P0 — Critical Gaps

| Tool Category | Specific Tools | Controls Served | Why Critical |
|---|---|---|---|
| **Secrets Management** | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault (deeper) | NIST SC-12, SC-28, IA-5(7), ISO A.8.24, UCF-DAT-3 | Current key_vault connector is Azure-only and shallow. No secret rotation tracking, no certificate lifecycle, no PKI posture. Every framework needs encryption key management evidence. |
| **Container / K8s Security** | Aqua Security, Sysdig, Falco, K8s admission controllers | NIST CM-7, SI-3, SI-7, SA-11, ISO A.8.25, A.8.31, UCF-DEV-5, UCF-EPP-2 | EDR connectors don't cover runtime container security, image scanning, or K8s RBAC posture. |
| **CI/CD Pipeline Security** | GitHub Actions audit logs, GitLab CI, Jenkins, ArgoCD | NIST CM-3, CM-5, SA-10, SA-11, ISO A.8.25, A.8.31, UCF-DEV-1 | ServiceNow covers change tickets but not actual deployment pipeline — no code signing, branch protection, approval gates, or deployment audit trails. |

### P1 — High Value

| Tool Category | Specific Tools | Controls Served | Why Important |
|---|---|---|---|
| **Third-Party Risk** | SecurityScorecard, BitSight, Prevalent, RiskRecon | NIST SR-2, SR-5, SA-9, ISO A.5.19–A.5.22, SOC CC9.2, UCF-TPM-1 | OneTrust covers privacy but not vendor security ratings. No continuous vendor risk scoring, breach notification monitoring, or vendor questionnaire tracking. |
| **Network Firewall Analysis** | Palo Alto Panorama, Fortinet FortiManager, Cisco FMC | NIST SC-7, AC-4, ISO A.8.20–A.8.22, UCF-NET-1–NET-3 | Cloudflare WAF is covered but not next-gen firewall rule analysis. No firewall change tracking, rule conflict detection, or network segmentation validation. |
| **Certificate Lifecycle** | Venafi, AWS Certificate Manager, cert-manager | NIST SC-12, SC-17, ISO A.8.24, UCF-DAT-3 | No cert expiration tracking, CA trust chain validation, or certificate transparency log monitoring. |
| **Communication Audit** | Slack Enterprise Grid, Microsoft Teams compliance, Zoom | NIST AU-2, AC-22, ISO A.5.14, UCF-LOG-1 | Proofpoint covers email threats but not internal communication audit logs. No evidence communication channels are monitored per policy. |
| **CMDB / Asset Discovery** | ServiceNow CMDB, Device42, Snipe-IT, Axonius | NIST CM-8, PM-5, ISO A.5.9, UCF-ASM-1, UCF-CFG-6 | CM-8 (asset inventory) is proxied by EDR agent lists and cloud resource APIs. No authoritative CMDB integration for complete asset baseline. |
| **DNS Security** | Cisco Umbrella, Infoblox, AWS Route 53 Resolver | NIST SC-7, SC-20, SC-21, UCF-NET-1 | No DNS filtering evidence, DNSSEC validation, or DNS query logging. |

### P2 — Incremental Coverage

| Tool Category | Specific Tools | Controls Served | Notes |
|---|---|---|---|
| **DR Orchestration** | Zerto, AWS Elastic DR, Azure Site Recovery | NIST CP-4, CP-7, CP-10, UCF-BCP-3, BCP-4 | Veeam covers backup but not full DR orchestration — failover testing, RTO measurement, runbook execution. |
| **Contract/Legal Management** | Ironclad, DocuSign CLM, Icertis | NIST SA-4, PS-6, SR-2, ISO A.5.20, UCF-TPM-2 | Employment agreements via Workday but vendor contracts, SLAs, DPAs not tracked. |
| **Privileged Session Recording** | BeyondTrust, Delinea | NIST AC-2(4), AU-14, ISO A.8.18, UCF-IAM-4 | CyberArk covers PAM but no connector for BeyondTrust or Delinea. |
| **Data Classification Scanning** | Amazon Macie, Azure Purview data scanning, BigID | NIST RA-2, SC-16, ISO A.5.12–A.5.13, UCF-DAT-4 | Purview covers DLP alerts but not data discovery/classification scanning results. |
| **WAF / API Gateway** | AWS WAF, Azure Front Door, Akamai, Imperva | NIST SC-7(11), SI-4, ISO A.8.23, UCF-NET-6 | Cloudflare WAF exists but no AWS WAF, Azure WAF, or dedicated API security (Salt Security, Noname). |
| **Browser Isolation / ZTNA** | Zscaler ZPA, Netskope Private Access | NIST AC-17, SC-7, ISO A.6.7, UCF-IAM-5, UCF-NET-1 | No zero-trust network access posture evidence beyond Cloudflare Access. |
| **BambooHR** | BambooHR API | Same as Workday | For SMBs that don't use Workday — same HRIS controls, different API. |

---

## 6. Control Families Still Weakest

| Family | Framework | Controls | Current State | Remaining Gap |
|---|---|---|---|---|
| **SA (System Acquisition)** | NIST | 138 | Mostly `checks: []` | Deeply procedural — contract language, SDLC process, acquisition planning. Partially addressed by Snyk (SA-11) and ServiceNow (SA-4). |
| **PE (Physical/Environmental)** | NIST | 61 | Mostly `checks: []` | Verkada covers entry controls but not environmental monitoring (temperature, humidity, fire suppression, power). Would need BMS/SCADA integrations. |
| **PL (Planning)** | NIST | 19 | All `checks: []` | Entirely procedural — security plans, rules of behavior. Confluence helps verify document existence but not content adequacy. |
| **PM (Program Management)** | NIST | 40 | Almost all `checks: []` | Governance — risk management strategy, enterprise architecture, threat awareness program. Inherently human-judgment controls. AI narrator can generate narratives but can't automate assessment. |

---

## 7. Implementation Priority Stack

### Phase 1 — Foundation (Unblocks Everything)

| Item | Effort | Impact |
|---|---|---|
| REST API layer (FastAPI) | Large | Unblocks UI, integrations, everything downstream |
| Authentication / RBAC | Medium | Prerequisite for multi-user access |
| Immutable audit trail (hash chain on evidence) | Medium | Auditor trust requirement |

### Phase 2 — Audit Readiness

| Item | Effort | Impact |
|---|---|---|
| Temporal evidence packaging (audit period scoping) | Medium | Required for SOC 2 Type II, ISO annual audits |
| Control-level posture aggregation | Medium | Turns raw findings into actionable posture |
| Evidence sufficiency scoring | Medium | Answers "do I have enough evidence for this audit?" |
| SOC 2 / ISO specific report templates | Medium | Auditor workflow support |

### Phase 3 — Connector Expansion

| Item | Effort | Impact |
|---|---|---|
| HashiCorp Vault / secrets management connector | Small | High framework multiplier |
| Container/K8s security connector | Medium | Critical for cloud-native orgs |
| CI/CD pipeline audit connector | Small | Closes DevSecOps evidence loop |
| Third-party risk connector (SecurityScorecard) | Small | Unlocks vendor risk controls |

### Phase 4 — Operational Intelligence

| Item | Effort | Impact |
|---|---|---|
| Alert routing (Slack/PagerDuty webhooks) | Small | Operationalizes posture monitoring |
| Posture trend storage + scoring | Medium | Enables drift detection dashboards |
| Blast radius analysis queries | Medium | Impact cascade visualization |
| Natural language policy interpretation | Large | Customer policy → technical control validation |
| Compensating control reasoning | Medium | Real-world audit flexibility |

### Phase 5 — Polish

| Item | Effort | Impact |
|---|---|---|
| PDF report generation | Medium | Auditor deliverable format |
| OSCAL schema validation | Small | Export quality assurance |
| Alembic migrations | Small | Schema evolution support |
| Framework-specific risk scoring | Medium | Per-framework severity weighting |
| Cross-framework conflict detection | Medium | Identifies contradictory requirements |

---

## Appendix: Current Connector Inventory (36 Total)

### Cloud (10)
AWS, Azure, GCP, Oracle Cloud (OCI), IBM Cloud, Alibaba Cloud, DigitalOcean, Huawei Cloud, OVHcloud, Cloudflare

### EDR (3)
CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne

### IAM (4)
Okta, Entra ID (Azure AD), CyberArk PAM, SailPoint IdentityNow

### Scanner (3)
Tenable.io, Qualys VMDR, Wiz

### CSPM (1)
Prisma Cloud

### SIEM (3)
Microsoft Sentinel, Splunk, Elastic Security

### HRIS (1)
Workday

### ITSM (1)
ServiceNow

### Training (1)
KnowBe4

### Code Security (1)
Snyk

### DLP (1)
Microsoft Purview

### Backup (1)
Veeam

### MDM (1)
Microsoft Intune

### GRC / Document Management (2)
Confluence, OneTrust

### Physical Security (1)
Verkada

### Email Security (1)
Proofpoint

### AI Tracking (1)
MLflow

### Custom (1)
Webhook/Push Receiver
