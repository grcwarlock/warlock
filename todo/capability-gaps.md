# Warlock Capability Gaps — Build Backlog

Generated 2026-03-22 from capability-matrix.md analysis against current codebase.
762 total capabilities identified, ~540 implemented, ~222 remaining.

Priority: P0 = blocking/essential, P1 = high-value, P2 = differentiator, P3 = future
Effort: S = <1 day, M = 1-3 days, L = 3-5 days, XL = 1+ week

---

## Domain 1: Compliance Posture Views (12 gaps)

- [ ] **CPV-1** (P1, M) — Compliance posture by deployment model (cloud/on-premise/hybrid) and service model (IaaS/PaaS/SaaS)
- [ ] **CPV-2** (P1, M) — Compliance posture by business unit / organizational unit (requires org_unit field on SystemProfile or Finding)
- [ ] **CPV-3** (P2, M) — Peer benchmarking against anonymized industry cohorts by sector and size
- [ ] **CPV-4** (P1, S) — Continuous authority to operate (cATO) dashboard showing real-time ATO health per system
- [ ] **CPV-5** (P1, M) — Pareto analysis: 20% of control families causing 80% of failures
- [ ] **CPV-6** (P1, S) — Finding diff view showing what changed in a specific resource between consecutive scans
- [ ] **CPV-7** (P2, S) — AI confidence distribution across assessments with low-confidence flagging
- [ ] **CPV-8** (P2, M) — Platform health dashboard: API latency, job status, connector sync health
- [ ] **CPV-9** (P3, M) — Usage analytics: active users, features used, reports generated
- [ ] **CPV-10** (P1, M) — Forecasting: project when current remediation velocity achieves target compliance levels
- [ ] **CPV-11** (P1, S) — Multi-cloud compliance posture: unified status across AWS, Azure, GCP in single view
- [ ] **CPV-12** (P2, S) — Common control provider identification: which systems provide evidence satisfying most frameworks

## Domain 2: Risk Quantification & Management (25 gaps)

- [ ] **RQM-1** (P1, M) — Custom threat scenario definition with user-specified frequency and impact ranges via CLI
- [ ] **RQM-2** (P1, M) — What-if analysis: hypothetical scenarios with modified effectiveness values
- [ ] **RQM-3** (P1, S) — Cost-of-noncompliance estimator projecting potential fines based on open findings
- [ ] **RQM-4** (P1, M) — Risk acceptance auto-re-evaluation triggers: severity_change, new_finding, time_elapsed
- [ ] **RQM-5** (P1, S) — Risk acceptance trigger evaluation engine scanning all active acceptances
- [ ] **RQM-6** (P2, M) — Compensating control effectiveness scoring (0-100) with review frequency tracking
- [ ] **RQM-7** (P2, S) — Compensating control influence on posture scoring
- [ ] **RQM-8** (P1, M) — Risk register export with POA&M cross-references
- [ ] **RQM-9** (P2, M) — Risk interconnection mapping showing dependencies and cascade effects
- [ ] **RQM-10** (P2, L) — Emerging risk identification using AI to scan threat intelligence feeds
- [ ] **RQM-11** (P1, M) — Risk lifecycle management: identification -> assessment -> treatment -> monitoring -> closure
- [ ] **RQM-12** (P2, M) — Risk treatment cost-benefit analysis: simulation with/without proposed control
- [ ] **RQM-13** (P1, S) — Supply chain concentration analysis counting control dependencies per vendor
- [ ] **RQM-14** (P1, M) — Vendor blast radius computation: all systems, frameworks, controls affected if vendor fails
- [ ] **RQM-15** (P2, S) — Fourth-party risk visibility through concentration analysis
- [ ] **RQM-16** (P2, M) — Impact propagation across dependent systems
- [ ] **RQM-17** (P2, M) — Compliance simulation scenarios with what-if parameters
- [ ] **RQM-18** (P1, S) — Board-level risk dashboard: total_mean_ale, total_var_95, scenario count, appetite breach status
- [ ] **RQM-19** (P1, M) — Framework-specific risk scenarios: GDPR (20M EUR), HIPAA (PHI breach), PCI DSS (payment compromise)
- [ ] **RQM-20** (P2, L) — Loss exceedance curve generation as (threshold, probability) tuples
- [ ] **RQM-21** (P1, S) — Inherent risk calculation: simulation with control_effectiveness=0.0
- [ ] **RQM-22** (P1, S) — Risk reduction ROI: inherent ALE minus residual ALE vs control implementation cost
- [ ] **RQM-23** (P2, M) — Risk culture metrics: posture trending, drift detection, MTTR, uptime tracking
- [ ] **RQM-24** (P1, S) — Organizational risk posture aggregation rolling up control-level to framework-level
- [ ] **RQM-25** (P2, M) — Cross-framework risk correlation through UCF crosswalk mappings

## Domain 3: POA&M Management (5 gaps)

- [ ] **POAM-1** (P1, S) — POA&M cost tracking and resource allocation documentation
- [ ] **POAM-2** (P1, M) — POA&M dependencies between items
- [ ] **POAM-3** (P1, S) — POA&M escalation triggers for overdue items (auto-notify)
- [ ] **POAM-4** (P1, S) — POA&M bulk operations: batch update status, assignment, priority
- [ ] **POAM-5** (P2, S) — POA&M aging report showing delay counts, scheduled vs actual completion

## Domain 4: Issue Management (9 gaps)

- [ ] **ISS-1** (P1, S) — Issue comment threading with @mention notifications
- [ ] **ISS-2** (P2, M) — Issue delegation and out-of-office routing
- [ ] **ISS-3** (P1, S) — Issue remediation velocity tracking: average time from creation to resolution by priority
- [ ] **ISS-4** (P2, S) — Issue watch list: subscription to status changes on specific issues
- [ ] **ISS-5** (P1, S) — Task assignment with due dates, priority levels, assignee selection
- [ ] **ISS-6** (P1, M) — Issue SLA enforcement with auto-escalation when remediation exceeds SLA
- [ ] **ISS-7** (P1, M) — Root cause analysis grouping related findings under common root cause
- [ ] **ISS-8** (P2, M) — Issue delegation workflow with out-of-office routing
- [ ] **ISS-9** (P1, S) — Issue bulk operations: bulk change severity, bulk add to POA&M

## Domain 5: Vendor Risk Management (10 gaps)

- [ ] **VRM-1** (P1, M) — Vendor risk scoring weight customization per organization
- [ ] **VRM-2** (P1, M) — Questionnaire score computation from responses (0-100)
- [ ] **VRM-3** (P2, M) — AI auto-suggest answers for questionnaire responses with confidence scores
- [ ] **VRM-4** (P1, M) — Questionnaire lifecycle: draft->sent->in_progress->completed->reviewed->accepted/rejected
- [ ] **VRM-5** (P1, M) — Vendor contract management: agreement terms, security obligations, audit rights, renewal dates
- [ ] **VRM-6** (P1, M) — Vendor continuous monitoring integrating external risk rating feeds
- [ ] **VRM-7** (P1, M) — Vendor access inventory showing which systems/data each vendor accesses
- [ ] **VRM-8** (P1, M) — Vendor compliance mapping: which controls each vendor's services satisfy
- [ ] **VRM-9** (P2, M) — Vendor lifecycle management as formal workflow: onboarding -> monitoring -> offboarding
- [ ] **VRM-10** (P1, S) — Vendor portfolio risk report: all vendors with scores, levels, recommendations

## Domain 6: Audit Management (10 gaps)

- [ ] **AUD-1** (P1, M) — Audit scoping: define in-scope and excluded controls per audit period
- [ ] **AUD-2** (P2, M) — Audit workpaper management with structured templates and reviewer sign-off
- [ ] **AUD-3** (P1, M) — Audit finding tracking from draft through management response to closure verification
- [ ] **AUD-4** (P2, L) — External audit coordination portal with secure read-only access
- [ ] **AUD-5** (P1, M) — Continuous auditing capability: automated tests between formal engagements
- [ ] **AUD-6** (P1, M) — Sampling methodology: statistically significant sample selection from large control populations
- [ ] **AUD-7** (P1, S) — Audit observation recording with severity, affected controls, management response
- [ ] **AUD-8** (P1, S) — Evidence review queue listing evidence awaiting auditor review
- [ ] **AUD-9** (P1, M) — Evidence validity rules: minimum freshness, required artifact types per control
- [ ] **AUD-10** (P2, M) — Compliance certification package assembly: policies, evidence, test results, attestations

## Domain 7: Framework Operations (7 gaps)

- [ ] **FWK-1** (P1, M) — Shared responsibility matrix generation: customer vs provider responsibilities per control
- [ ] **FWK-2** (P1, S) — Baseline tailoring: add/remove controls per system from standard baseline
- [ ] **FWK-3** (P1, M) — Control implementation status tracking per system: planned/implemented/partially/not-implemented
- [ ] **FWK-4** (P2, M) — Custom framework definition: import proprietary frameworks in YAML or OSCAL format
- [ ] **FWK-5** (P1, M) — Framework versioning workflow: handle version transitions without losing historical data
- [ ] **FWK-6** (P1, S) — Control gap analysis: controls with no assertions, no evidence, no test coverage (consolidated)
- [ ] **FWK-7** (P2, M) — Semantic control mapping via embedding providers for vector similarity

## Domain 8: Security Posture & Vulnerability Management (15 gaps)

- [ ] **SEC-1** (P1, M) — Vulnerability prioritization by CVSS, exploitability, asset criticality, exposure context
- [ ] **SEC-2** (P1, S) — False positive handling with documented justification and review workflow
- [ ] **SEC-3** (P1, M) — Cross-scanner vulnerability correlation (same host detected by multiple tools)
- [ ] **SEC-4** (P1, S) — Vulnerability count by resource type, cloud account, density per asset
- [ ] **SEC-5** (P1, S) — Vulnerability backlog burndown tracking
- [ ] **SEC-6** (P1, M) — CIS benchmark compliance via OPA/Rego policies (add CIS-specific rules)
- [ ] **SEC-7** (P1, M) — Configuration compliance by cloud service (EC2, S3, IAM, VPC, RDS)
- [ ] **SEC-8** (P1, S) — Encryption status tracking across data silos (at-rest, in-transit)
- [ ] **SEC-9** (P1, S) — Logging coverage analysis (access_logging_enabled)
- [ ] **SEC-10** (P1, M) — Security group / NSG / firewall rule analysis
- [ ] **SEC-11** (P1, M) — Network exposure analysis: public-facing resources across all cloud accounts
- [ ] **SEC-12** (P1, M) — Cross-account access and trust relationship analysis
- [ ] **SEC-13** (P2, M) — IOC correlation from CrowdStrike, SentinelOne, Defender
- [ ] **SEC-14** (P2, M) — Threat actor TTP mapping to control coverage gaps
- [ ] **SEC-15** (P1, S) — Patch compliance tracking against SLA timelines per asset criticality

## Domain 9: Identity & Access Management (5 gaps)

- [ ] **IAM-1** (P1, M) — Cloud entitlement management: excessive permissions detection with least-privilege recommendations
- [ ] **IAM-2** (P1, S) — IdP group membership changes over time (detect lateral privilege changes)
- [ ] **IAM-3** (P1, S) — Background check status and completion tracking
- [ ] **IAM-4** (P1, S) — NDA and agreement signing status tracking
- [ ] **IAM-5** (P2, M) — Phishing simulation score integration from KnowBe4 data

## Domain 10: Privacy & Data Governance (5 gaps)

- [ ] **PRV-1** (P1, M) — Privacy rights request management with jurisdiction-specific deadline tracking
- [ ] **PRV-2** (P1, S) — Cookie consent and tracking transparency documentation
- [ ] **PRV-3** (P1, M) — Privacy impact assessment (PIA) management with templates (formalize existing DPIA)
- [ ] **PRV-4** (P1, M) — Data processing activity register: purposes, legal bases, categories, retention periods
- [ ] **PRV-5** (P2, M) — AI governance analysis of privacy policy gaps with recommendations

## Domain 11: Reporting & Export (15 gaps)

- [ ] **RPT-1** (P0, L) — HTML compliance report with print CSS, status color coding, branding
- [ ] **RPT-2** (P0, L) — PDF compliance report via weasyprint with fallback
- [ ] **RPT-3** (P0, M) — Export to Excel/CSV for any tabular data in the platform
- [ ] **RPT-4** (P1, M) — SOC 2 Type II report with management assertion, criteria, test procedures, results, exceptions
- [ ] **RPT-5** (P1, M) — ISO 27001 Statement of Applicability (SoA) in JSON and CSV
- [ ] **RPT-6** (P1, M) — FedRAMP-specific report generation (POA&M, SSP, SAR formats)
- [ ] **RPT-7** (P1, S) — Compliance gap report: every non-passing control with root cause categorization
- [ ] **RPT-8** (P1, S) — Remediation progress report: closure rates vs targets by team, framework, severity
- [ ] **RPT-9** (P2, M) — Regulatory submission preparation: format data for specific regulatory body requirements
- [ ] **RPT-10** (P2, M) — Board presentation mode: large fonts, clean layouts, strategic metrics only
- [ ] **RPT-11** (P1, M) — Lake consumption: pre-joined views for Vanta, Drata, AuditBoard, ServiceNow
- [ ] **RPT-12** (P2, M) — Lake consumption: BI/JDBC endpoint for Looker, Metabase, Python
- [ ] **RPT-13** (P1, M) — Lake consumption: regulatory filing templates (GDPR DPA 72h, SEC 8-K, DORA CSIRT)
- [ ] **RPT-14** (P2, M) — Lake consumption: questionnaire auto-fill (SIG, CAIQ, DDQ) from compliance data
- [ ] **RPT-15** (P2, S) — Lake consumption: trust center badges per framework with last_updated

## Domain 12: Automation & Pipeline (10 gaps)

- [ ] **AUT-1** (P0, M) — Alert generation for real-time compliance event notification (beyond audit trail)
- [ ] **AUT-2** (P1, M) — Email alert channel (SMTP integration: SES, SendGrid, Postmark)
- [ ] **AUT-3** (P1, S) — Alert deduplication cache with configurable cooldown_minutes
- [ ] **AUT-4** (P1, M) — Escalation chains: control owner -> team lead -> CISO when unresolved
- [ ] **AUT-5** (P0, L) — CI/CD pipeline integration: GitHub Actions compliance checks on PRs
- [ ] **AUT-6** (P1, M) — Infrastructure-as-code compliance scanning: Terraform, CloudFormation templates
- [ ] **AUT-7** (P1, M) — DevSecOps pipeline gates blocking non-compliant deployments
- [ ] **AUT-8** (P1, M) — GitHub/GitLab integration: compliance status checks on pull requests
- [ ] **AUT-9** (P2, M) — Auto-close resolved findings when remediation is verified
- [ ] **AUT-10** (P2, M) — Auto-assign based on resource owner from CMDB/asset inventory

## Domain 13: Data Lake & Analytics (10 gaps)

- [ ] **DLA-1** (P1, M) — Saved queries and query templates for common analytics
- [ ] **DLA-2** (P1, S) — Data quality scoring and freshness SLAs per source
- [ ] **DLA-3** (P2, L) — Time-travel queries via Iceberg format for historical compliance state
- [ ] **DLA-4** (P2, M) — Data archival with hot/warm/cold storage tiers
- [ ] **DLA-5** (P2, M) — Backup and disaster recovery with point-in-time restore
- [ ] **DLA-6** (P1, M) — Cohort analysis: remediation rates across teams, business units, time periods
- [ ] **DLA-7** (P2, M) — Lake SCD: slowly changing dimension history for compliance entities
- [ ] **DLA-8** (P1, S) — Lake bridges: connect analytical data back to operational workflows
- [ ] **DLA-9** (P2, M) — Lake MCP tools: Model Context Protocol interfaces for lake data
- [ ] **DLA-10** (P2, M) — Historical risk analysis over time series from lake data

## Domain 14: Collaboration & Workflow (10 gaps)

- [ ] **COL-1** (P1, M) — Multi-level approval chains with configurable approver roles per workflow type
- [ ] **COL-2** (P2, M) — Shared dashboards for collaborative team views
- [ ] **COL-3** (P2, M) — Team workspaces scoped to business units, projects, compliance programs
- [ ] **COL-4** (P1, S) — Activity feed showing recent changes with filters by user, object type, action
- [ ] **COL-5** (P1, M) — Stakeholder RACI matrix per control family
- [ ] **COL-6** (P2, M) — Calendar integration: Google Calendar, Outlook sync for assessment deadlines
- [ ] **COL-7** (P2, M) — New regulation alert using AI horizon scanning
- [ ] **COL-8** (P1, M) — Regulatory change management with impact assessment workflows
- [ ] **COL-9** (P1, M) — Policy document management with version control, authorship, review cycles
- [ ] **COL-10** (P2, M) — Release management compliance: CAB approval and testing verification

## Domain 15: Connectors & Integration (8 gaps)

- [ ] **INT-1** (P0, L) — SSO integration via SAML 2.0 and OIDC (Okta, Azure AD, Google Workspace)
- [ ] **INT-2** (P1, L) — SCIM provisioning for automated user lifecycle from identity provider
- [ ] **INT-3** (P1, M) — Jira integration: bidirectional ticket sync from findings and POA&Ms
- [ ] **INT-4** (P1, M) — ServiceNow integration: push findings to incident/change tables
- [ ] **INT-5** (P2, M) — Microsoft Teams integration: adaptive cards for notifications and approvals
- [ ] **INT-6** (P2, M) — Zapier/n8n integration via webhook triggers and API actions
- [ ] **INT-7** (P2, M) — STIX/TAXII integration: consume threat intelligence feeds
- [ ] **INT-8** (P1, M) — Terraform provider: manage compliance as infrastructure-as-code

## Domain 16: Security & Access Control (3 gaps)

- [ ] **SAC-1** (P1, M) — IP allowlisting for API and UI access
- [ ] **SAC-2** (P1, M) — Session management: configurable timeout, concurrent limits, forced logout
- [ ] **SAC-3** (P1, S) — Data classification tagging with sensitivity labels on findings and evidence

## Domain 17: AI & Machine Learning (5 gaps)

- [ ] **AIM-1** (P2, L) — AI-powered horizon scanning for new regulations and compliance changes
- [ ] **AIM-2** (P1, M) — AI governance analysis of policy gaps with recommendations
- [ ] **AIM-3** (P1, S) — AI model attribution tracking per ControlResult (which model, confidence, token count)
- [ ] **AIM-4** (P2, M) — AI DevTools for debugging AI assessments (prompt viewer, response analyzer)
- [ ] **AIM-5** (P1, M) — Risk prediction and forecasting using historical posture data with AI

## Domain 18: Platform & Infrastructure (10 gaps)

- [ ] **PLT-1** (P2, XL) — Multi-tenancy with tenant-level data isolation and independent configurations
- [ ] **PLT-2** (P2, L) — White-label capability for MSSPs
- [ ] **PLT-3** (P1, M) — Role hierarchy with inheritable permissions
- [ ] **PLT-4** (P2, M) — Delegated administration for business unit leaders
- [ ] **PLT-5** (P2, M) — Sandbox/staging environment for testing before production
- [ ] **PLT-6** (P1, L) — Data import from legacy GRC tools: Archer, ServiceNow GRC, MetricStream, spreadsheets
- [ ] **PLT-7** (P1, M) — Bulk data import via CSV, JSON, Excel for any entity type
- [ ] **PLT-8** (P2, L) — SDK and client libraries: Python, JavaScript/TypeScript, Go
- [ ] **PLT-9** (P1, M) — GraphQL API layer for flexible queries with field selection
- [ ] **PLT-10** (P2, M) — Asset inventory integration mapping findings to IT assets and business processes

## Domain 19: Incident & Business Continuity (5 gaps)

- [ ] **IBC-1** (P1, M) — Incident playbook library per type (data breach, ransomware, insider threat, DDoS)
- [ ] **IBC-2** (P1, M) — Incident impact assessment: affected records, notification requirements, financial exposure
- [ ] **IBC-3** (P2, M) — Crisis communication templates for different scenarios
- [ ] **IBC-4** (P1, M) — BCP/DR exercise management: tabletop, functional, full-scale with outcome capture
- [ ] **IBC-5** (P1, S) — Operational risk event tracking across all connector types

## Domain 20: Search, UX & Accessibility (10 gaps)

- [ ] **UX-1** (P1, L) — Full-text search across findings, controls, policies, risks, vendors, evidence
- [ ] **UX-2** (P2, M) — Natural language query translation to structured queries
- [ ] **UX-3** (P2, M) — Saved filters with one-click recall and team sharing
- [ ] **UX-4** (P2, S) — Smart suggestions: auto-complete based on search history and context
- [ ] **UX-5** (P3, S) — Recent items and favorites bar
- [ ] **UX-6** (P2, M) — Faceted search with dynamic filter counts
- [ ] **UX-7** (P1, S) — Global command palette for rapid CLI navigation
- [ ] **UX-8** (P2, S) — Fuzzy matching tolerating typos and abbreviations in CLI
- [ ] **UX-9** (P3, L) — Mobile-optimized approval workflows (requires frontend)
- [ ] **UX-10** (P3, M) — Offline evidence collection with later sync

---

## Summary

| Domain | Total Caps | Implemented | Gaps | P0 | P1 | P2 | P3 |
|--------|-----------|-------------|------|----|----|----|----|
| 1. Compliance Views | 82 | 70 | 12 | 0 | 7 | 4 | 1 |
| 2. Risk Management | 65 | 40 | 25 | 0 | 14 | 11 | 0 |
| 3. POA&M | 25 | 20 | 5 | 0 | 4 | 1 | 0 |
| 4. Issues | 30 | 21 | 9 | 0 | 6 | 3 | 0 |
| 5. Vendor Risk | 35 | 25 | 10 | 0 | 7 | 3 | 0 |
| 6. Audit | 45 | 35 | 10 | 0 | 7 | 3 | 0 |
| 7. Frameworks | 40 | 33 | 7 | 0 | 4 | 3 | 0 |
| 8. Security/Vuln | 55 | 40 | 15 | 0 | 12 | 3 | 0 |
| 9. IAM | 25 | 20 | 5 | 0 | 4 | 1 | 0 |
| 10. Privacy | 30 | 25 | 5 | 0 | 4 | 1 | 0 |
| 11. Reporting | 45 | 30 | 15 | 2 | 6 | 5 | 0 |
| 12. Automation | 50 | 40 | 10 | 2 | 5 | 3 | 0 |
| 13. Data Lake | 40 | 30 | 10 | 0 | 4 | 6 | 0 |
| 14. Collaboration | 30 | 20 | 10 | 0 | 5 | 5 | 0 |
| 15. Integration | 35 | 27 | 8 | 1 | 4 | 3 | 0 |
| 16. Security/Access | 25 | 22 | 3 | 0 | 3 | 0 | 0 |
| 17. AI/ML | 25 | 20 | 5 | 0 | 3 | 2 | 0 |
| 18. Platform | 45 | 35 | 10 | 0 | 4 | 5 | 1 |
| 19. Incident/BCP | 20 | 15 | 5 | 0 | 4 | 1 | 0 |
| 20. Search/UX | 15 | 5 | 10 | 0 | 2 | 5 | 3 |
| **Total** | **762** | **~543** | **~219** | **5** | **107** | **68** | **5** |

## Recommended Build Order

### Sprint 1: P0 Blockers (5 items, ~1 week)
- RPT-1, RPT-2, RPT-3 — Export formats (HTML, PDF, Excel)
- AUT-1 — Real-time alert generation
- AUT-5 — CI/CD compliance gate (GitHub Actions)
- INT-1 — SSO (SAML/OIDC)

### Sprint 2: High-Value P1 (top 20, ~2 weeks)
- Risk: RQM-1, RQM-2, RQM-3, RQM-11, RQM-18, RQM-21, RQM-22
- Reporting: RPT-4 (SOC 2), RPT-5 (ISO SoA), RPT-6 (FedRAMP)
- Automation: AUT-2 (email), AUT-4 (escalation chains), AUT-8 (GitHub checks)
- Integration: INT-3 (Jira), INT-4 (ServiceNow)
- Security: SEC-1 (vuln prioritization), SEC-3 (cross-scanner correlation)
- Platform: PLT-6 (legacy import), PLT-7 (bulk import)

### Sprint 3: Remaining P1 (~2 weeks)
- All remaining P1 items across all domains

### Sprint 4+: P2 Differentiators (ongoing)
- Multi-tenancy, white-label, SDK, advanced AI, search/UX
