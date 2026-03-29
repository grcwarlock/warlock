# Run 4: Market Gap Analysis — Warlock vs. GRC Platform Landscape (2025-2026)

Generated: 2026-03-29

---

## Section 1: Market Landscape Summary

### 1.1 Continuous Compliance Automation (Drata, Vanta, Secureframe, Sprinto, Scrut)

These platforms own the SMB-to-midmarket compliance automation space. Their core value proposition: connect your cloud/SaaS stack, automatically collect evidence, map it to frameworks, and stay audit-ready continuously.

**Key features Warlock should benchmark against:**

| Feature | Drata | Vanta | Secureframe | Sprinto | Scrut |
|---|---|---|---|---|---|
| Agent-based endpoint monitoring | Yes | Yes | Yes | Yes | No |
| Auto-evidence collection (screenshots, configs) | Yes | Yes | Yes | Yes | Yes |
| Employee onboarding/offboarding compliance | Yes | Yes | Yes | Yes | Yes |
| Trust center (public portal) | Yes | Yes | Yes | Yes | Yes |
| Auditor portal (direct assessor access) | Yes | Yes | Yes | No | No |
| Policy template library (100+) | Yes | Yes | Yes | Yes | Yes |
| Policy acknowledgment tracking | Yes | Yes | Yes | Yes | Yes |
| Custom control mapping | Yes | Yes | Yes | Limited | Yes |
| Multi-framework crosswalk | Yes | Yes | Yes | Yes | Yes |
| Vendor risk management | Yes | Yes | Yes | Limited | Yes |
| Penetration test management | Yes | Yes | Yes | No | Yes |
| Security awareness training (built-in) | Yes (via partner) | Yes (via partner) | No | Yes | No |
| Real-time compliance monitoring | Yes | Yes | Yes | Yes | Yes |
| AI-powered remediation guidance | Yes | Yes | Yes | No | No |
| Custom integrations (API/webhook) | Yes | Yes | Yes | Limited | Yes |
| SCIM/SSO provisioning | Yes | Yes | Yes | Yes | Yes |
| Risk register | Yes | Yes | Yes | Yes | Yes |
| GRC workflow automation | Yes | Yes | Yes | Yes | Yes |
| Compliance-as-code | No | No | No | No | No |

**Drata differentiators:**
- Autopilot: continuous monitoring with auto-remediation for common misconfigs (e.g., auto-enable MFA, auto-encrypt S3 buckets)
- 85+ native integrations, agent for macOS/Windows/Linux
- Built-in compliance AI assistant ("Drata AI") for evidence descriptions, control narratives, risk assessments
- Auditor workflow: auditors get their own portal with sampling, request lists, and direct evidence access
- Custom frameworks: customers can define entirely custom frameworks with custom controls

**Vanta differentiators:**
- Trust Management Platform positioning (beyond just compliance)
- Vendor risk management with automated questionnaire sending and AI-powered response review
- Risk scoring and quantification (not just qualitative)
- Vanta AI: auto-generates policy documents, gap analysis, and evidence descriptions
- Access reviews: built-in periodic access review campaigns
- Largest integration catalog (~300+ native)
- Custom tests: write custom compliance tests in the UI

**Secureframe differentiators:**
- AI-first approach: Comply AI auto-maps evidence, writes control descriptions, fills questionnaires
- Personnel management: employee compliance tracking with automated training assignments
- Continuous monitoring with customizable alert thresholds
- Risk management with quantitative scoring

**Sprinto differentiators:**
- "Compliance autopilot" — automated evidence collection + remediation workflows in one
- Role-based task assignment with SLA tracking
- Audit project management built into the platform

**Scrut differentiators:**
- Cloud-native risk-first approach
- SmartMap: AI-powered control-to-evidence mapping
- Multi-entity management for holding companies

### 1.2 Enterprise GRC Platforms (ServiceNow GRC, Archer, AuditBoard, LogicGate)

These serve large enterprises with complex organizational structures, heavy customization needs, and integration with existing IT infrastructure.

**ServiceNow GRC differentiators:**
- Deep ITSM integration (incidents, changes, CIs all feed GRC automatically)
- CMDB-driven scoping: authorization boundaries derived from the CMDB, not manually drawn
- Workflow engine: visual workflow builder for any GRC process
- Continuous authorization / continuous monitoring (ConMon) native
- Policy lifecycle: author, review, approve, publish, attest, retire — full lifecycle
- Integrated Risk Management (IRM): operational risk, IT risk, vendor risk unified
- Issue and exception management with automated escalation
- Regulatory change management: subscribe to regulatory feeds, auto-assess impact
- Performance Analytics: pre-built GRC dashboards, KRIs, trend analysis
- Multi-entity/multi-tenant enterprise support

**Archer (RSA) differentiators:**
- Extreme configurability (custom objects, relationships, calculated fields)
- Content subscriptions: pre-built frameworks, threat libraries, regulatory content
- Quantitative risk analysis modules (Monte Carlo, loss event management)
- Operational resilience modules (BCP/DR integrated with risk)
- Data feeds: automated data imports from any structured source
- Archer Exchange: marketplace of pre-built use cases and integrations

**AuditBoard differentiators:**
- Cross-functional GRC: audit, risk, compliance, ESG/sustainability in one platform
- SOX compliance automation (ITGC + business process controls)
- WorkStream collaboration: real-time collaboration between audit teams and control owners
- Evidence request workflows with automated reminders and escalation
- AI-powered risk assessment and issue prioritization
- Board-level reporting with pre-built executive dashboards
- Integrated internal audit management with fieldwork tracking

**LogicGate differentiators:**
- No-code workflow builder for custom GRC processes
- Risk Cloud: flexible risk quantification and aggregation
- API-first architecture for custom integrations
- Pre-built application templates for common GRC use cases
- Dynamic reporting with drag-and-drop dashboard builder
- Regulatory change intelligence feed

### 1.3 Privacy-First Platforms (OneTrust)

**OneTrust differentiators:**
- Market leader in privacy management (consent, DSAR, cookie compliance, data mapping)
- Privacy Impact Assessment (PIA/DPIA) workflow engine with AI-assisted completion
- Consent management platform with multi-channel support (web, mobile, CTV, IoT)
- Data discovery and classification across structured/unstructured data stores
- Cross-border transfer impact assessments (Schrems II compliance)
- Vendor risk management with privacy-specific questionnaires
- Cookie compliance scanning and auto-categorization
- Universal consent preference management
- Records of Processing Activities (ROPA) automation
- Incident and breach management with notification timeline tracking
- ESG/sustainability modules
- AI governance module (model inventory, risk assessment, bias detection)
- Regulatory intelligence: curated regulatory change feed with impact assessment

### 1.4 Cloud Security Posture (Wiz)

**Wiz differentiators (GRC-adjacent):**
- Agentless cloud scanning across AWS, Azure, GCP, OCI, Alibaba (full inventory in minutes)
- Security graph: attack path analysis connecting vulnerabilities, misconfigurations, identities, and data
- Risk-based prioritization: EPSS, exploitability, reachability, data exposure context
- Container and Kubernetes security (image scanning, runtime, admission control)
- Cloud Detection and Response (CDR): real-time threat detection
- SBOM and code scanning integration
- Compliance frameworks mapped to actual cloud resource state
- DSPM (Data Security Posture Management): data classification and flow tracking
- AI-SPM: AI security posture management (model inventory, training data risks)
- Ticket routing and ITSM integration for remediation workflows

### 1.5 Data-First GRC (Anecdotes)

**Anecdotes differentiators:**
- "GRC OS" positioning: compliance as a data engineering problem (closest philosophical match to Warlock)
- Connector-driven evidence collection from 100+ tools
- Unified data model: one control graph that maps to multiple frameworks
- Automated control testing with programmable test logic
- Cross-framework mapping with shared evidence
- Gap analysis with evidence sufficiency scoring
- Compliance analytics: trend analysis, coverage metrics, risk quantification
- Customizable dashboards and reporting
- API-first architecture

### 1.6 Emerging Pattern: Compliance Copilots

Across all platforms, 2025-2026 sees convergence on AI copilots that:
- Auto-generate SSP narratives, policy documents, and control descriptions
- Fill vendor questionnaires (SIG, CAIQ, DDQ) from existing evidence
- Explain findings in plain English with remediation guidance
- Predict compliance drift before it happens
- Summarize audit readiness in natural language
- Answer "are we compliant with X?" in conversational form
- Auto-classify and map new evidence to controls
- Generate executive briefings from raw compliance data

---

## Section 2: Table Stakes Gaps (Every Competitor Has This; Warlock Does Not or Has Partially)

### TS-1: Agent-Based Endpoint Monitoring
**Status:** Missing entirely
**What competitors do:** Drata, Vanta, Secureframe, and Sprinto all ship lightweight agents for macOS, Windows, and Linux that verify disk encryption, screen lock, OS patches, antivirus, and MDM enrollment in real time. This data feeds directly into compliance evidence.
**Warlock gap:** Warlock has MDM connectors (Intune, Jamf, Kandji, etc.) that pull data from MDM APIs, but no native endpoint agent. This means Warlock depends entirely on third-party MDM deployment to verify endpoint compliance. For organizations without MDM, there is no endpoint compliance data.
**Impact:** Significant for SMB/startup market where MDM is not yet deployed. Competitors win deals on "install our agent and get compliant" simplicity.

### TS-2: Policy Template Library with Acknowledgment Tracking
**Status:** Partial — policy management exists, template library is thin
**What competitors do:** 100+ pre-written, lawyer-reviewed policy templates (Acceptable Use, Data Classification, Incident Response, etc.) that can be customized and published. Employees are assigned policies, must acknowledge them, and acknowledgment is tracked as evidence. Auto-reminders for unsigned policies. Version control with re-acknowledgment on major changes.
**Warlock gap:** `warlock/workflows/policy_manager.py` handles policy lifecycle (draft, review, approve, publish, retire) and `warlock/cli/policy_cmd.py` exposes CLI commands. But there is no pre-built template library, no employee-facing acknowledgment portal, and no acknowledgment tracking as evidence. The system manages policy metadata but not policy content delivery and attestation at scale.
**Impact:** Auditors ask "show me that all employees have read the Acceptable Use Policy" — without acknowledgment tracking, customers must use a separate tool.

### TS-3: Employee Compliance Onboarding/Offboarding Workflows
**Status:** Partial — HRIS connectors exist, lifecycle workflows are skeletal
**What competitors do:** When a new employee appears in Workday/BambooHR, automatically: assign security training, send policies for acknowledgment, create accounts with appropriate RBAC, trigger background check, enroll in MFA. On termination: revoke all access within SLA, archive email, reassign assets, update vendor access lists.
**Warlock gap:** HRIS connectors (Workday, BambooHR, Gusto, Rippling, ADP, UKG, SAP, Paylocity) collect personnel data. `warlock/workflows/personnel.py` exists. But there is no automated workflow engine that triggers actions based on hire/term events. The training module tracks completion but does not auto-assign. Access review is manual.
**Impact:** Table stakes for SOC 2 CC6.2/CC6.3 evidence. Without automated onboarding/offboarding, customers do this manually or with another tool.

### TS-4: Evidence Request Workflow (Auditor Collaboration)
**Status:** Partial — evidence vault and packaging exist, but no request/response workflow
**What competitors do:** Auditors log into a portal, create evidence requests (PBC lists), assign them to control owners with deadlines. Control owners upload or link evidence. Auditors mark items as received/accepted/rejected. Auto-reminders for overdue items. Full audit trail of all interactions.
**Warlock gap:** `warlock/export/auditor.py` generates evidence packages. `warlock/api/trust_portal.py` has NDA-gated document access. `warlock/workflows/audit_manager.py` manages engagements. But there is no interactive request/response workflow between auditors and control owners. No PBC (Provided By Client) list management. No "request evidence for AC-2" with assignment and tracking.
**Impact:** Every audit engagement requires this workflow. Without it, Warlock cannot serve as the system of record during an active audit.

### TS-5: Access Review Campaigns
**Status:** Partial — CLI command exists, but no campaign workflow
**What competitors do:** Periodic (quarterly/annual) access review campaigns: managers review their team's access, approve/revoke, certify the review. Full audit trail. Auto-detection of excessive privileges. Integration with IAM providers for automated revocation.
**Warlock gap:** `warlock/cli/access_review_cmd.py` exists and IAM connectors (Okta, Entra ID, CyberArk, etc.) collect access data. But there is no campaign management: no "create a Q1 2026 access review, assign to managers, track completion, escalate overdue." The review process is ad-hoc, not campaign-driven.
**Impact:** SOC 2 CC6.1, ISO 27001 A.9.2.5, NIST AC-2(j) all expect periodic, documented access reviews.

### TS-6: Interactive Dashboard Builder / Custom Dashboards
**Status:** Partial — pre-built dashboards exist (TUI + frontend), but no drag-and-drop builder
**What competitors do:** Users create custom dashboards by dragging compliance widgets (charts, tables, KRIs, posture gauges). Save, share, schedule delivery. Personalized views for CISO, auditor, control owner, board member.
**Warlock gap:** Frontend has a fixed Dashboard page. TUI has 7 fixed screens. CLI has `dashboard` commands with pre-built views. Lake analytics supports custom SQL queries. But there is no self-service dashboard builder where a non-technical user can create their own compliance view without writing SQL or code.
**Impact:** Every enterprise buyer expects personalized dashboards. CISOs want their view, board members want theirs, auditors want theirs.

### TS-7: Notification Engine (Email, Slack, Teams Digests)
**Status:** Partial — alert integrations exist, but no configurable notification center
**What competitors do:** Configurable notification preferences: which events trigger notifications, via which channel (email, Slack, Teams, PagerDuty), to whom, with what frequency (real-time, daily digest, weekly summary). Role-based defaults.
**Warlock gap:** `warlock/export/alerts.py` and integrations for Slack, Teams, PagerDuty, email exist. `warlock/export/scheduled_reports.py` handles periodic delivery. But there is no unified notification preferences engine where users configure their own alert preferences. No digest mode. No "notify me when my POA&M is overdue" user preference.
**Impact:** Users drown in alerts or get none. Configurable notifications are expected in any SaaS platform.

### TS-8: In-App Guided Remediation Workflows
**Status:** Partial — remediation guidance exists in data, but no step-by-step wizard
**What competitors do:** When a control fails, the platform shows a guided remediation workflow: step 1 (fix the config), step 2 (verify), step 3 (re-assess), step 4 (mark complete). With links to the specific resource in AWS/Azure/GCP console. Some include auto-remediation (Drata Autopilot).
**Warlock gap:** `warlock/assessors/remediation_loader.py` loads remediation templates. `warlock/cli/remediation_cmd.py` exposes remediation commands. Framework YAML files have remediation guidance. AI can generate remediation suggestions. But there is no interactive step-by-step wizard in the TUI or frontend that walks a user through fixing a specific finding end-to-end. No auto-remediation of cloud misconfigurations.
**Impact:** The gap between "you have a finding" and "you fixed it" is where users need the most help. Competitors reduce this to clicks; Warlock leaves it as information.

### TS-9: Multi-Language / Localization Support
**Status:** Missing entirely
**What competitors do:** OneTrust, ServiceNow, and Archer support multiple languages for UI, policies, and reports. Critical for global deployments. GDPR/LGPD/APPI compliance requires local-language notices.
**Warlock gap:** All UI, CLI output, reports, and policies are English-only.
**Impact:** Blocks international enterprise adoption. Less critical for initial market but becomes table stakes at scale.

### TS-10: SOC 2 Type II Readiness Score with Gap-to-Audit Timeline
**Status:** Partial — readiness score exists, but no audit timeline projection
**What competitors do:** "You are 73% ready for SOC 2 Type II. Based on your current remediation velocity, you will be audit-ready in 47 days. Here are the 12 gaps blocking you, ranked by effort." With a timeline visualization.
**Warlock gap:** `warlock comply readiness-score` gives a 0-100 score. `warlock comply quick-wins` lists lowest-effort fixes. `warlock assessors/simulation.py` projects compliance state at a future date. But these are separate tools — there is no unified "readiness-to-audit" view that combines score, timeline projection, and prioritized gap list in one experience.
**Impact:** This is the #1 question every compliance buyer asks: "how long until we're audit-ready?"

---

## Section 3: Differentiator Opportunities (Would Make Warlock Stand Out)

### D-1: Compliance-as-Code (Warlock's Unique Advantage)
**Status:** Already partially implemented — this is Warlock's core differentiator, but not fully exploited
**Opportunity:** No competitor offers true compliance-as-code where controls are assertions in Python/Rego, evidence pipelines are testable code, and compliance state is version-controlled. Drata/Vanta/Secureframe are SaaS platforms with proprietary backends. Warlock's open, code-first approach is unique.
**What to build:** Package the compliance-as-code story more explicitly:
- `warlock init` scaffolds a compliance-as-code repository for a new org
- Controls defined in YAML/Rego, version-controlled alongside infrastructure code
- CI/CD gates that fail builds on compliance regression
- Terraform modules that embed compliance checks
- PR-level compliance impact analysis ("this PR would violate AC-2")
- Compliance state stored as code artifacts, diffable between commits

### D-2: CMDB-Driven Authorization Boundaries
**Status:** System profiles exist, but not CMDB-integrated
**Opportunity:** ServiceNow's biggest advantage is CMDB-driven scoping. Warlock already has system profiles and asset connectors (Axonius, runZero, ServiceNow CMDB). Build the bridge: auto-derive FedRAMP authorization boundaries and SOC 2 system descriptions from CMDB/asset inventory data.
**What to build:**
- Import asset inventory from Axonius/runZero/ServiceNow CMDB
- Auto-generate system boundaries (which assets are in-scope for which framework)
- Visualize the boundary as an architecture diagram
- Auto-scope controls based on boundary membership
- Detect boundary drift (new asset added but not scoped)

### D-3: Attack Path to Compliance Mapping
**Status:** Missing — Wiz-adjacent capability
**Opportunity:** Bridge the gap between security posture (attack paths, exploitability, blast radius) and compliance posture. When a vulnerability is exploitable AND on a path to sensitive data, the compliance impact is higher than an isolated finding. No GRC platform does this well.
**What to build:**
- Ingest attack path data from Wiz, Orca, Prisma connectors
- Map attack paths to affected controls (not just individual findings)
- Risk-adjust compliance scores based on actual exploitability
- "This AC-2 violation is critical because it's on an attack path to PII"
- Blast radius visualization: one misconfigured IAM role affects 14 controls across 3 frameworks

### D-4: Regulatory Intelligence with Automated Impact Assessment
**Status:** Partial — `warlock/ai/horizon_scanning.py` has hardcoded regulatory deadlines
**Opportunity:** OneTrust charges premium for regulatory intelligence feeds. Warlock can build an AI-powered regulatory change engine that:
- Monitors regulatory sources (Federal Register, EU Official Journal, state AG offices)
- Uses AI to classify relevance to the organization's framework portfolio
- Auto-generates gap analysis: "NIS2 Article 21 maps to these 8 NIST 800-53 controls you already have, plus 3 new requirements"
- Provides implementation timelines based on current maturity
- Tracks regulatory change through draft/final/enforcement stages

### D-5: Continuous Authorization (cATO) Engine
**Status:** Partial — ConMon commands exist, but not a full cATO pipeline
**Opportunity:** FedRAMP is moving toward continuous authorization. DoD has cATO. The market needs a platform that implements the full cATO loop: continuous monitoring -> automated boundary change detection -> incremental assessment -> authorization decision support.
**What to build:**
- Real-time posture monitoring against FedRAMP baseline
- Automated significant change detection (new service, new data flow, new interconnection)
- Incremental assessment scoping (only re-assess what changed)
- Authorization decision package generation (SSP delta, test results, POA&M updates)
- ConMon deliverable automation (monthly vulnerability scans, annual penetration tests, quarterly assessments)

### D-6: Supply Chain Compliance (C-SCRM)
**Status:** SBOM connectors exist (Syft/Grype, Snyk, FOSSA), but no compliance mapping
**Opportunity:** NIST 800-161 (C-SCRM), CMMC supplier flow-down, EU CRA — supply chain compliance is exploding. No platform handles this well.
**What to build:**
- SBOM ingestion and compliance mapping (which components have known vulnerabilities affecting which controls?)
- Supplier compliance inheritance (vendor's SOC 2 covers these controls for us)
- Flow-down requirement tracking (which CMMC controls must our suppliers also meet?)
- Software supply chain risk scoring (using SLSA levels, VEX, EPSS)
- Vendor security posture correlation with compliance status

### D-7: Privacy Engineering Automation
**Status:** Privacy commands exist (DSAR, breach notification, ROPA), but not differentiated
**Opportunity:** Bridge OneTrust's privacy management with Warlock's data engineering approach:
- Auto-generate data flow diagrams from actual infrastructure scanning (not manual drawing)
- PIA/DPIA automation: pre-populate assessments from technical architecture data
- Consent receipt management with cryptographic proof
- Automated cross-border transfer mapping (which data crosses which borders, based on actual cloud regions and data flows)
- Retention policy enforcement: verify that data is actually deleted when retention expires (not just scheduled)
- Privacy metrics: DSAR response time, consent rates, data minimization scores

### D-8: AI Governance Module (EU AI Act / NIST AI RMF)
**Status:** EU AI Act framework (33 controls) and ISO 42001 (39 controls) exist, plus AI/ML connectors (MLflow, SageMaker, etc.)
**Opportunity:** Warlock has the framework definitions but no operational AI governance:
- AI model inventory from MLflow/SageMaker/Weights & Biases connectors
- Model risk classification (EU AI Act risk tiers)
- Bias and fairness monitoring integration
- Training data provenance tracking
- Model performance monitoring with compliance thresholds
- Human oversight requirement enforcement
- Transparency documentation generation (Article 13 EU AI Act)

### D-9: Compliance Velocity Metrics and Benchmarking
**Status:** MTTD/MTTR exist, but no velocity metrics or benchmarks
**Opportunity:** Answer "how fast is our compliance program improving?" and "how do we compare to similar companies?"
- Mean Time to Compliance (MTTC): time from gap detection to compliant state
- Compliance velocity: rate of gap closure over time
- Evidence freshness distribution
- Control test pass rate trends
- Anonymous benchmarking: "your SOC 2 readiness score is in the 72nd percentile for Series B SaaS companies"
- Cost-per-control metrics

### D-10: Offline-First / Air-Gapped Deployment
**Status:** Warlock runs locally (SQLite, DuckDB), but not packaged for air-gapped
**Opportunity:** FedRAMP High, DoD IL5/IL6, and classified environments need air-gapped GRC platforms. No cloud-native GRC platform supports this. Warlock's local-first architecture is uniquely positioned.
**What to build:**
- Package Warlock as a single binary or container with all dependencies
- Offline framework definitions, policy templates, remediation guidance
- Air-gapped update mechanism (USB/media transfer of framework updates)
- STIG-hardened deployment configuration
- Documentation for DISA STIG/SRG compliance of Warlock itself

---

## Section 4: Data Lake and Analytics Gaps

### 4.1 Current State

Warlock's GRC data lake (`warlock/lake/`) is significantly more advanced than most competitors:
- **Zones:** Raw, standardized, curated (medallion architecture)
- **Storage:** Parquet files with Iceberg schema generation
- **Query:** DuckDB embedded engine
- **RAG:** TF-IDF semantic search over curated zone (FAISS optional)
- **Aggregations:** Pre-computed framework posture, control family posture
- **Bridges:** Cross-domain relationship tables (crosswalks, entity relationships, data flows)
- **Consumption:** GRC tool export, BI/direct queries, regulatory filing, questionnaire automation, trust center
- **Backfill:** OLTP-to-lake backfill for historical data
- **Reconciliation:** OLTP/lake consistency checks
- **SCD:** Slowly changing dimension tracking
- **Lake analytics CLI:** 20 commands for SQL query, anomaly detection, trends, lineage, data quality

This is ahead of most competitors. The gaps are in the analytics and visualization layer on top of the lake.

### DL-1: Real-Time Streaming Analytics
**Status:** Missing — lake writes are batch (after pipeline runs)
**What's needed:**
- Streaming ingestion from webhook/event sources (not just batch connector runs)
- Real-time materialized views that update as events arrive
- Streaming anomaly detection (not just batch)
- WebSocket/SSE push to frontend dashboards for live updates
- Event-driven alerting from stream processing (not polling)
**Competitors:** Wiz has real-time cloud event processing. ServiceNow has real-time event correlation.

### DL-2: Predictive Risk Modeling
**Status:** Missing — risk engine is quantitative (FAIR, Monte Carlo) but not predictive
**What's needed:**
- Time-series forecasting: predict compliance score at future date based on historical trend
- Control failure prediction: which controls are likely to drift based on patterns
- Vulnerability arrival rate modeling: predict future finding volume
- Risk trend extrapolation: if current trajectory continues, when does risk exceed appetite?
- Seasonal pattern detection: do certain controls degrade after quarterly deploys?
**Competitors:** ServiceNow has predictive intelligence. Drata AI hints at predictive capabilities.

### DL-3: Natural Language Analytics (Beyond RAG)
**Status:** Partial — `warlock lake query` and `warlock ask` support NL queries via RAG
**What's needed:**
- Text-to-SQL: "show me all critical findings in AWS from the last 30 days" -> generates SQL, runs against lake, returns formatted results
- Follow-up queries: "now group by control family" should work in context
- Visualization suggestions: "chart this over time" should produce a graph
- Explain mode: "why is AC-2 non-compliant?" should trace from control result through findings to raw evidence
- Saved queries with parameterization and sharing
**Competitors:** OneTrust and ServiceNow have natural language querying. Drata AI has conversational compliance.

### DL-4: Custom Report Builder
**Status:** Missing — reports are code-generated (SOC 2, ISO 27001, FedRAMP, executive, board)
**What's needed:**
- Drag-and-drop report builder with compliance-specific widgets
- Template library: board report, CISO monthly, auditor evidence package, vendor review
- Data binding: connect widgets to lake queries or OLTP data
- Export: PDF, PPTX, HTML, Excel with white-label branding
- Scheduling: auto-generate and deliver on cadence
- Version history: show how a report changed quarter-over-quarter
**Competitors:** AuditBoard, ServiceNow, Archer all have sophisticated report builders.

### DL-5: Data Visualization Library
**Status:** Missing in web UI / Partial in TUI (Rich tables and sparklines)
**What's needed:**
- Compliance heatmaps (framework x control family, colored by posture)
- Risk heat maps (likelihood x impact, interactive)
- Posture trend lines (sparklines, area charts over time)
- Sunburst/treemap for framework hierarchy
- Network graph for control crosswalks and entity relationships
- Sankey diagram for data flows
- Gantt charts for POA&M timelines
- Geographic maps for data residency visualization
**Competitors:** Every platform has rich visualization. Wiz's security graph is best-in-class.

### DL-6: Anomaly Detection Improvements
**Status:** Partial — `warlock/assessors/anomaly.py` has Isolation Forest + Z-score/IQR fallback
**What's needed:**
- Baseline learning: automatically learn normal behavior per connector/control
- Contextual anomalies: "this is unusual FOR a Tuesday" not just "this is unusual overall"
- Multi-dimensional anomalies: correlate volume + severity + source simultaneously
- Anomaly explanation: not just "anomaly detected" but "finding volume from CrowdStrike increased 3x compared to 30-day average, coinciding with a new rule deployment"
- Feedback loop: user marks anomaly as "expected" to improve future detection
**Competitors:** Wiz, ServiceNow have mature anomaly detection.

### DL-7: Compliance Velocity and Trend Metrics
**Status:** Partial — posture snapshots and time-series exist, but velocity metrics are not computed
**What's needed:**
- Time-to-compliance: how long from first gap detection to compliant state, per control
- Compliance velocity: rate of gap closure (gaps closed per week, trending up/down)
- Evidence freshness decay curves
- Control test failure rate trends with confidence intervals
- Drift frequency and recovery time per control
- "Compliance debt" metric: accumulated age of all open gaps, weighted by severity
**Competitors:** Drata shows compliance trends. AuditBoard has compliance velocity dashboards.

### DL-8: Auditor Self-Service Analytics Portal
**Status:** Missing — auditors get evidence packages but cannot self-serve
**What's needed:**
- Read-only portal where auditors log in and run their own queries
- Pre-built auditor views: sampling interface, population query, exception detail
- Evidence search and filter by control, date range, system
- Audit trail of auditor queries (what did the auditor look at?)
- Comment/annotation system on evidence items
- Export to auditor workpapers (Excel, PDF)
**Competitors:** Drata, Vanta, AuditBoard all have auditor portals.

### DL-9: Data Retention and Archival Policies
**Status:** Partial — `warlock/workflows/retention.py` and `warlock/workflows/evidence_retention.py` handle retention schedules
**What's needed:**
- Lake-level retention: automated tiering from hot (Parquet) to warm (compressed) to cold (archived) to deleted
- Retention policy per data classification (PII retained differently than config data)
- Legal hold integration: freeze data subject to litigation hold
- Defensible deletion: prove data was deleted according to schedule (deletion certificate)
- Retention compliance dashboard: which data is within/outside its retention window?
**Competitors:** OneTrust has data retention lifecycle management. ServiceNow has archival policies.

### DL-10: Data Lineage Visualization
**Status:** Partial — lake has lineage tracking via `lake-analytics lineage` CLI command
**What's needed:**
- Visual lineage graph: raw event -> finding -> control mapping -> control result -> posture
- Click-through: click any node in the lineage to see full detail
- Impact analysis: "if this connector stops working, which controls lose evidence?"
- Freshness propagation: show which downstream data is stale because an upstream source stopped
- Integration with data quality checks: lineage nodes flagged when quality degrades
**Competitors:** Anecdotes positions heavily on data lineage.

### DL-11: Industry Benchmarking Data
**Status:** Missing entirely
**What's needed:**
- Opt-in anonymous telemetry: aggregate compliance posture across Warlock deployments
- Benchmark reports: "your NIST 800-53 compliance score is in the Xth percentile for your industry/size"
- Control-level benchmarks: "92% of SaaS companies have AC-2 compliant vs. your 78%"
- Framework adoption stats: which frameworks are most common for your industry
- Mean MTTC/MTTR benchmarks by industry vertical
**Competitors:** Vanta and Drata hint at benchmarking. SecurityScorecard provides industry comparisons. This is largely uncharted in GRC.

---

## Section 5: Prioritized TODO List

### P0 — Critical: Must Have for Market Viability (2-3 months)

| ID | Gap | Description | Effort | Dependencies |
|---|---|---|---|---|
| P0-1 | TS-4 | Evidence request workflow (PBC list management, auditor <-> control owner collaboration) | L | Audit manager, evidence vault |
| P0-2 | TS-10 | Unified readiness-to-audit view (score + timeline + prioritized gaps in one experience) | M | Simulation engine, readiness score |
| P0-3 | TS-6 | Dashboard builder MVP (widget library + drag-and-drop layout, save/share) | XL | Frontend, lake queries |
| P0-4 | DL-5 | Compliance visualization library (heatmaps, trend charts, posture gauges) for web UI | L | Frontend charting library |
| P0-5 | TS-8 | Guided remediation wizard (step-by-step fix flow with links to cloud console) | M | Remediation loader, frontend |
| P0-6 | TS-7 | Notification preferences engine (per-user channel/frequency config) | M | Existing alert integrations |
| P0-7 | TS-2 | Policy template library (50+ templates) + employee acknowledgment tracking | L | Policy manager |

### P1 — High: Competitive Differentiation (3-6 months)

| ID | Gap | Description | Effort | Dependencies |
|---|---|---|---|---|
| P1-1 | D-1 | Compliance-as-code packaging (`warlock init`, CI gates, PR-level compliance analysis) | L | Pipeline, assessors |
| P1-2 | D-5 | Continuous authorization (cATO) engine with automated ConMon deliverables | XL | FedRAMP export, posture, drift |
| P1-3 | TS-5 | Access review campaign management (create, assign, track, certify, escalate) | M | IAM connectors, access review cmd |
| P1-4 | DL-8 | Auditor self-service analytics portal (read-only, query, sample, export) | L | Trust portal, lake queries |
| P1-5 | DL-3 | Text-to-SQL natural language analytics (NL -> SQL -> results -> chart) | L | Lake query engine, AI service |
| P1-6 | D-2 | CMDB-driven authorization boundaries (auto-scope from asset inventory) | L | Axonius/runZero/CMDB connectors |
| P1-7 | D-4 | Regulatory intelligence engine (monitor, classify, auto-gap-analyze) | L | Horizon scanning, AI service |
| P1-8 | TS-3 | Employee lifecycle automation (onboarding/offboarding triggered by HRIS events) | L | HRIS connectors, workflows |
| P1-9 | DL-7 | Compliance velocity metrics (MTTC, gap closure rate, compliance debt) | M | Posture snapshots, MTTD/MTTR |
| P1-10 | D-3 | Attack path to compliance mapping (Wiz/Orca attack paths -> control impact) | M | Wiz/Orca connectors |
| P1-11 | DL-1 | Streaming ingestion MVP (webhook events -> lake in real-time, WebSocket push to UI) | L | Lake writer, pipeline bus |
| P1-12 | DL-4 | Custom report builder (template library, data binding, export, scheduling) | XL | Frontend, lake queries, export |

### P2 — Medium: Market Expansion (6-12 months)

| ID | Gap | Description | Effort | Dependencies |
|---|---|---|---|---|
| P2-1 | D-8 | AI governance module (model inventory, risk classification, bias monitoring) | L | AI/ML connectors, EU AI Act framework |
| P2-2 | D-6 | Supply chain compliance (SBOM -> compliance mapping, supplier flow-down) | L | SBOM connectors, CMMC framework |
| P2-3 | D-7 | Privacy engineering automation (auto data flow diagrams, PIA pre-population) | L | Privacy connectors, data lake |
| P2-4 | DL-2 | Predictive risk modeling (time-series forecasting, control failure prediction) | L | Lake aggregations, risk engine |
| P2-5 | DL-10 | Data lineage visualization (interactive graph, impact analysis, freshness propagation) | M | Lake lineage, frontend |
| P2-6 | DL-6 | Anomaly detection improvements (baseline learning, contextual, explainable) | M | Anomaly module |
| P2-7 | TS-1 | Endpoint agent MVP (macOS disk encryption + screen lock + OS patch verification) | XL | New codebase (Swift/Go/Rust) |
| P2-8 | DL-9 | Lake retention tiering (hot/warm/cold/delete with retention policies) | M | Lake zones, retention workflows |
| P2-9 | D-10 | Air-gapped deployment packaging (single container, offline frameworks) | M | Build system |
| P2-10 | D-9 | Compliance benchmarking (opt-in anonymous aggregation, industry percentiles) | L | Telemetry infrastructure |

### P3 — Low: Future Roadmap (12+ months)

| ID | Gap | Description | Effort | Dependencies |
|---|---|---|---|---|
| P3-1 | TS-9 | Multi-language / localization support | XL | All UI, CLI, reports |
| P3-2 | DL-11 | Industry benchmarking data (requires sufficient deployment scale) | L | P2-10 telemetry |
| P3-3 | — | SOX compliance module (ITGC + business process controls) | XL | New framework + assertions |
| P3-4 | — | ESG/sustainability reporting module | L | New framework |
| P3-5 | — | No-code workflow builder (LogicGate-style visual GRC process design) | XL | Frontend, workflow engine |
| P3-6 | — | Auto-remediation engine (Drata Autopilot equivalent: auto-fix cloud misconfigs) | XL | Cloud SDKs, safety controls |
| P3-7 | — | Mobile app (compliance status, approvals, notifications on the go) | XL | API, mobile framework |

---

## Appendix: Warlock's Existing Strengths (Do NOT Rebuild)

These are areas where Warlock is ahead of or at parity with the market. Protect these investments:

1. **Pipeline architecture**: 4-stage hash-chained pipeline is more rigorous than any competitor
2. **Connector breadth**: 361 connectors rivals Vanta (~300) and exceeds most others
3. **Framework coverage**: 14 frameworks with 1,996 controls and crosswalks exceeds all SMB platforms
4. **Data lake**: DuckDB + Parquet + Iceberg is a genuine engineering advantage over competitors using only OLTP
5. **OSCAL support**: Deterministic OSCAL export (SSP, assessment results, POA&M) is unique in the market
6. **Multi-tier assessment**: Assertions -> AI -> OPA -> inheritance is more sophisticated than competitors' binary pass/fail
7. **Risk quantification**: FAIR + Monte Carlo simulation exceeds most competitors' qualitative heatmaps
8. **Trust portal**: NDA-gated document access with HMAC-signed download links
9. **Vendor risk**: SecurityScorecard/BitSight integration with composite scoring
10. **Compliance-as-code DNA**: OPA/Rego policies, Terraform modules, policy-as-code — no competitor has this
11. **CLI depth**: 686 commands across 73 modules — no competitor has a CLI at all
12. **TUI**: Interactive terminal dashboard is unique in the market
13. **AI integration**: Multi-provider (Anthropic, OpenAI, Gemini, Ollama) with conversation, RAG, questionnaire auto-fill
14. **Questionnaire automation**: SIG, CAIQ, DDQ auto-fill from evidence corpus
15. **Audit simulation**: Project compliance state at future dates
16. **Drift detection**: Compliance drift with change event correlation
17. **Anomaly detection**: Isolation Forest + statistical fallback for compliance telemetry
18. **MTTD/MTTR**: Compliance-specific detection and remediation time tracking
19. **GDPR engineering**: Anonymization-based erasure, not deletion — preserves audit chain
20. **Horizon scanning**: Regulatory deadline tracking with emerging requirement detection
