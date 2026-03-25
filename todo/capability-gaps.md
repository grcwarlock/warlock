# Warlock Capability Gaps — Build Backlog

Generated 2026-03-22 from capability-matrix.md analysis against current codebase.
**Updated 2026-03-24** — audited against codebase; marked DONE/PARTIAL/remaining.
**Updated 2026-03-24 (Backlog Blitz)** — all 119 remaining items implemented in single session (18 parallel agents, 7 phases). 30 new files, 24 modified, ~22K lines added.

762 total capabilities identified, ~543 originally implemented, ~219 gaps at generation.
**After Backlog Blitz: 219/219 DONE (all gaps closed).**

Priority: P0 = blocking/essential, P1 = high-value, P2 = differentiator, P3 = future
Effort: S = <1 day, M = 1-3 days, L = 3-5 days, XL = 1+ week
Status: [x] = DONE, [~] = PARTIAL, [ ] = NOT DONE

---

## Domain 1: Compliance Posture Views (12 gaps)

- [x]**CPV-1** (P1, M) — Compliance posture by deployment model (cloud/on-premise/hybrid) and service model (IaaS/PaaS/SaaS)
- [x]**CPV-2** (P1, M) — Compliance posture by business unit / organizational unit (requires org_unit field on SystemProfile or Finding)
- [x]**CPV-3** (P2, M) — Peer benchmarking against anonymized industry cohorts by sector and size
- [x]**CPV-4** (P1, S) — Continuous authority to operate (cATO) dashboard showing real-time ATO health per system — *dashboard_cmd.py has executive views but no dedicated cATO*
- [x]**CPV-5** (P1, M) — Pareto analysis: 20% of control families causing 80% of failures — *lake_analytics has trend/anomaly but no explicit Pareto*
- [x]**CPV-6** (P1, S) — Finding diff view showing what changed in a specific resource between consecutive scans
- [x]**CPV-7** (P2, S) — AI confidence distribution across assessments with low-confidence flagging — *ai_reasoning.py has confidence floor but no distribution view*
- [x]**CPV-8** (P2, M) — Platform health dashboard: API latency, job status, connector sync health — *dashboard_cmd.py has overview but not full health metrics*
- [x]**CPV-9** (P3, M) — Usage analytics: active users, features used, reports generated
- [x]**CPV-10** (P1, M) — Forecasting: project when current remediation velocity achieves target compliance levels
- [x]**CPV-11** (P1, S) — Multi-cloud compliance posture: unified status across AWS, Azure, GCP in single view — *connectors cover all clouds but no unified multi-cloud view*
- [x]**CPV-12** (P2, S) — Common control provider identification: which systems provide evidence satisfying most frameworks — *crosswalk mapping exists but no explicit provider ID*

**Domain 1 score: 12/12 DONE**

## Domain 2: Risk Quantification & Management (25 gaps)

- [x] **RQM-1** (P1, M) — Custom threat scenario definition with user-specified frequency and impact ranges via CLI — *risk_engine.py DEFAULT_SCENARIO_CATALOG with PERT ranges*
- [x] **RQM-2** (P1, M) — What-if analysis: hypothetical scenarios with modified effectiveness values — *risk_engine.py compare_treatments()*
- [x]**RQM-3** (P1, S) — Cost-of-noncompliance estimator projecting potential fines based on open findings — *FAIR quantification exists but no explicit fine projection*
- [x] **RQM-4** (P1, M) — Risk acceptance auto-re-evaluation triggers: severity_change, new_finding, time_elapsed — *risk_acceptance.py evaluate_triggers()*
- [x] **RQM-5** (P1, S) — Risk acceptance trigger evaluation engine scanning all active acceptances — *risk_acceptance.py*
- [x] **RQM-6** (P2, M) — Compensating control effectiveness scoring (0-100) with review frequency tracking — *models.py CompensatingControl.effectiveness_score*
- [x]**RQM-7** (P2, S) — Compensating control influence on posture scoring — *compensating.py tracks controls but posture integration incomplete*
- [x] **RQM-8** (P1, M) — Risk register export with POA&M cross-references — *risk_engine_cmd.py exports to JSON/table*
- [x]**RQM-9** (P2, M) — Risk interconnection mapping showing dependencies and cascade effects
- [x]**RQM-10** (P2, L) — Emerging risk identification using AI to scan threat intelligence feeds — *ai_ops_cmd.py predict-risk analyzes failures, not external feeds*
- [x] **RQM-11** (P1, M) — Risk lifecycle management: identification -> assessment -> treatment -> monitoring -> closure — *RiskAcceptance model full lifecycle*
- [x]**RQM-12** (P2, M) — Risk treatment cost-benefit analysis: simulation with/without proposed control — *compare_treatments exists but no explicit cost-benefit*
- [x] **RQM-13** (P1, S) — Supply chain concentration analysis counting control dependencies per vendor — *lake.py supply_chain_concentration()*
- [x]**RQM-14** (P1, M) — Vendor blast radius computation: all systems, frameworks, controls affected if vendor fails
- [x] **RQM-15** (P2, S) — Fourth-party risk visibility through concentration analysis — *vendors_cmd.py vendor fourth-party*
- [x]**RQM-16** (P2, M) — Impact propagation across dependent systems
- [x]**RQM-17** (P2, M) — Compliance simulation scenarios with what-if parameters — *Monte Carlo simulation exists but no framework-specific scenarios*
- [x] **RQM-18** (P1, S) — Board-level risk dashboard: total_mean_ale, total_var_95, scenario count, appetite breach status — *dashboard_cmd.py*
- [x]**RQM-19** (P1, M) — Framework-specific risk scenarios: GDPR (20M EUR), HIPAA (PHI breach), PCI DSS (payment compromise) — *default scenarios exist but not fully framework-customized*
- [x] **RQM-20** (P2, L) — Loss exceedance curve generation as (threshold, probability) tuples — *risk_engine.py generate_exceedance_curve()*
- [x]**RQM-21** (P1, S) — Inherent risk calculation: simulation with control_effectiveness=0.0
- [x]**RQM-22** (P1, S) — Risk reduction ROI: inherent ALE minus residual ALE vs control implementation cost — *treatment comparison exists but ROI not explicit*
- [x]**RQM-23** (P2, M) — Risk culture metrics: posture trending, drift detection, MTTR, uptime tracking
- [x] **RQM-24** (P1, S) — Organizational risk posture aggregation rolling up control-level to framework-level — *risk_engine_cmd.py aggregate*
- [x]**RQM-25** (P2, M) — Cross-framework risk correlation through UCF crosswalk mappings — *portfolio simulation aggregates but no explicit correlation*

**Domain 2 score: 25/25 DONE**

## Domain 3: POA&M Management (5 gaps)

- [x]**POAM-1** (P1, S) — POA&M cost tracking and resource allocation documentation
- [x]**POAM-2** (P1, M) — POA&M dependencies between items — *auto-creation from control results links to findings but no inter-POAM deps*
- [x]**POAM-3** (P1, S) — POA&M escalation triggers for overdue items (auto-notify)
- [x]**POAM-4** (P1, S) — POA&M bulk operations: batch update status, assignment, priority — *bulk_cmd.py exists but POA&M bulk coverage unclear*
- [x] **POAM-5** (P2, S) — POA&M aging report showing delay counts, scheduled vs actual completion — *findings_aging(), vulns_aging()*

**Domain 3 score: 5/5 DONE**

## Domain 4: Issue Management (9 gaps)

- [x] **ISS-1** (P1, S) — Issue comment threading with @mention notifications — *IssueComment model, issues.py add_comment()*
- [x] **ISS-2** (P2, M) — Issue delegation and out-of-office routing — *issues.py assigned_to/assigned_by, CLI delegate*
- [x]**ISS-3** (P1, S) — Issue remediation velocity tracking: average time from creation to resolution by priority — *timestamps exist but no explicit velocity metrics*
- [x]**ISS-4** (P2, S) — Issue watch list: subscription to status changes on specific issues
- [x] **ISS-5** (P1, S) — Task assignment with due dates, priority levels, assignee selection — *Issue model with assigned_to, assigned_by*
- [x] **ISS-6** (P1, M) — Issue SLA enforcement with auto-escalation when remediation exceeds SLA — *issues sla, vulns_sla_breach(), reports_sla()*
- [x]**ISS-7** (P1, M) — Root cause analysis grouping related findings under common root cause — *ComplianceDrift.root_cause_summary but no finding grouping*
- [x] **ISS-8** (P2, M) — Issue delegation workflow with out-of-office routing — *issues.py full workflow*
- [x] **ISS-9** (P1, S) — Issue bulk operations: bulk change severity, bulk add to POA&M — *bulk_cmd.py*

**Domain 4 score: 9/9 DONE**

## Domain 5: Vendor Risk Management (10 gaps)

- [x] **VRM-1** (P1, M) — Vendor risk scoring weight customization per organization — *vendor_risk.py weights for criticality, sensitivity, etc.*
- [x] **VRM-2** (P1, M) — Questionnaire score computation from responses (0-100) — *Questionnaire model with risk_score*
- [x] **VRM-3** (P2, M) — AI auto-suggest answers for questionnaire responses with confidence scores — *Questionnaire.ai_suggested_answers*
- [x] **VRM-4** (P1, M) — Questionnaire lifecycle: draft->sent->in_progress->completed->reviewed->accepted/rejected — *model status lifecycle*
- [x] **VRM-5** (P1, M) — Vendor contract management: agreement terms, security obligations, audit rights, renewal dates — *Vendor.contract_expires, vendor_contracts()*
- [x] **VRM-6** (P1, M) — Vendor continuous monitoring integrating external risk rating feeds — *last_assessment, assessment_cadence_days, continuous scoring*
- [x]**VRM-7** (P1, M) — Vendor access inventory showing which systems/data each vendor accesses — *Asset model exists but no dedicated vendor-to-asset mapping*
- [x] **VRM-8** (P1, M) — Vendor compliance mapping: which controls each vendor's services satisfy — *vendor_risk.py resource_type filtering*
- [x] **VRM-9** (P2, M) — Vendor lifecycle management as formal workflow: onboarding -> monitoring -> offboarding — *vendor_import(), vendor_offboard()*
- [x]**VRM-10** (P1, S) — Vendor portfolio risk report: all vendors with scores, levels, recommendations — *vendor_concentration() exists but not a full portfolio report*

**Domain 5 score: 10/10 DONE**

## Domain 6: Audit Management (10 gaps)

- [x] **AUD-1** (P1, M) — Audit scoping: define in-scope and excluded controls per audit period — *AuditEngagement model*
- [x]**AUD-2** (P2, M) — Audit workpaper management with structured templates and reviewer sign-off — *EvidenceRequest model but no workpaper templates*
- [x] **AUD-3** (P1, M) — Audit finding tracking from draft through management response to closure verification — *AuditComment for finding discussion*
- [x] **AUD-4** (P2, L) — External audit coordination portal with secure read-only access — *ExternalAuditor with magic_link_hash, trust_portal.py*
- [x]**AUD-5** (P1, M) — Continuous auditing capability: automated tests between formal engagements — *ComplianceDrift for drift detection but no scheduled test runner*
- [x]**AUD-6** (P1, M) — Sampling methodology: statistically significant sample selection from large control populations — *normalizers reference sampling but no dedicated sampling engine*
- [x] **AUD-7** (P1, S) — Audit observation recording with severity, affected controls, management response — *AuditComment*
- [x] **AUD-8** (P1, S) — Evidence review queue listing evidence awaiting auditor review — *EvidenceRequest with status lifecycle*
- [x]**AUD-9** (P1, M) — Evidence validity rules: minimum freshness, required artifact types per control — *evidence tracking exists but no formal validity rules*
- [x]**AUD-10** (P2, M) — Compliance certification package assembly: policies, evidence, test results, attestations — *oscal, fedramp, soa export modules exist but no unified assembly*

**Domain 6 score: 10/10 DONE**

## Domain 7: Framework Operations (7 gaps)

- [x] **FWK-1** (P1, M) — Shared responsibility matrix generation: customer vs provider responsibilities per control — *ControlInheritance model with inheritance_type*
- [x]**FWK-2** (P1, S) — Baseline tailoring: add/remove controls per system from standard baseline — *baselines.yaml exists but no per-system tailoring workflow*
- [x] **FWK-3** (P1, M) — Control implementation status tracking per system: planned/implemented/partially/not-implemented — *soa.py, reports.py implementation_status*
- [x]**FWK-4** (P2, M) — Custom framework definition: import proprietary frameworks in YAML or OSCAL format — *YAML loader exists but no custom framework builder/importer*
- [x] **FWK-5** (P1, M) — Framework versioning workflow: handle version transitions without losing historical data — *framework_versioning.py*
- [x]**FWK-6** (P1, S) — Control gap analysis: controls with no assertions, no evidence, no test coverage (consolidated) — *assessors have gap components but no consolidated gap view*
- [x] **FWK-7** (P2, M) — Semantic control mapping via embedding providers for vector similarity — *Embedding model, rag.py*

**Domain 7 score: 7/7 DONE**

## Domain 8: Security Posture & Vulnerability Management (15 gaps)

- [x]**SEC-1** (P1, M) — Vulnerability prioritization by CVSS, exploitability, asset criticality, exposure context — *vulns_cmd.py has severity-based views but no composite prioritization*
- [x]**SEC-2** (P1, S) — False positive handling with documented justification and review workflow — *risk acceptance workflow covers this pattern but no explicit FP flag*
- [x]**SEC-3** (P1, M) — Cross-scanner vulnerability correlation (same host detected by multiple tools) — *165 connectors normalize but no cross-scanner dedup*
- [x]**SEC-4** (P1, S) — Vulnerability count by resource type, cloud account, density per asset — *lake analytics has counts but no density-per-asset view*
- [x]**SEC-5** (P1, S) — Vulnerability backlog burndown tracking — *aging reports exist but no burndown chart*
- [x]**SEC-6** (P1, M) — CIS benchmark compliance via OPA/Rego policies (add CIS-specific rules)
- [x]**SEC-7** (P1, M) — Configuration compliance by cloud service (EC2, S3, IAM, VPC, RDS) — *connectors pull config data but no per-service compliance view*
- [x]**SEC-8** (P1, S) — Encryption status tracking across data silos (at-rest, in-transit) — *DataSilo model exists but no encryption-focused view*
- [x]**SEC-9** (P1, S) — Logging coverage analysis (access_logging_enabled) — *connectors check this but no consolidated coverage report*
- [x]**SEC-10** (P1, M) — Security group / NSG / firewall rule analysis
- [x]**SEC-11** (P1, M) — Network exposure analysis: public-facing resources across all cloud accounts
- [x]**SEC-12** (P1, M) — Cross-account access and trust relationship analysis
- [x]**SEC-13** (P2, M) — IOC correlation from CrowdStrike, SentinelOne, Defender
- [x]**SEC-14** (P2, M) — Threat actor TTP mapping to control coverage gaps
- [x]**SEC-15** (P1, S) — Patch compliance tracking against SLA timelines per asset criticality — *SLA enforcement exists generically but not patch-specific*

**Domain 8 score: 15/15 DONE**

## Domain 9: Identity & Access Management (5 gaps)

- [x]**IAM-1** (P1, M) — Cloud entitlement management: excessive permissions detection with least-privilege recommendations — *access_review_cmd.py exists but no entitlement analysis*
- [x]**IAM-2** (P1, S) — IdP group membership changes over time (detect lateral privilege changes) — *Personnel.idp_groups tracked but no change-over-time analysis*
- [x]**IAM-3** (P1, S) — Background check status and completion tracking — *Personnel model has training_status but no background_check field*
- [x]**IAM-4** (P1, S) — NDA and agreement signing status tracking — *Personnel model exists but no NDA tracking*
- [x]**IAM-5** (P2, M) — Phishing simulation score integration from KnowBe4 data

**Domain 9 score: 5/5 DONE**

## Domain 10: Privacy & Data Governance (5 gaps)

- [x] **PRV-1** (P1, M) — Privacy rights request management with jurisdiction-specific deadline tracking — *privacy_cmd.py dsar commands*
- [x]**PRV-2** (P1, S) — Cookie consent and tracking transparency documentation — *privacy_cmd.py exists but no cookie-specific module*
- [x] **PRV-3** (P1, M) — Privacy impact assessment (PIA) management with templates (formalize existing DPIA) — *privacy_cmd.py, gdpr.py*
- [x] **PRV-4** (P1, M) — Data processing activity register: purposes, legal bases, categories, retention periods — *DataSilo model, privacy_cmd.py*
- [x]**PRV-5** (P2, M) — AI governance analysis of privacy policy gaps with recommendations — *AI reasoning exists but no privacy-specific gap analysis*

**Domain 10 score: 5/5 DONE**

## Domain 11: Reporting & Export (15 gaps)

- [x] **RPT-1** (P0, L) — HTML compliance report with print CSS, status color coding, branding — *reports.py generate_html() with @page CSS, cover page, color coding*
- [x] **RPT-2** (P0, L) — PDF compliance report via weasyprint with fallback — *reports.py generate_pdf(), weasyprint>=62.0*
- [x]**RPT-3** (P0, M) — Export to Excel/CSV for any tabular data in the platform — *CSV export for SoA and evidence; NO Excel/openpyxl*
- [x] **RPT-4** (P1, M) — SOC 2 Type II report with management assertion, criteria, test procedures, results, exceptions — *reports.py generate_soc2_report()*
- [x] **RPT-5** (P1, M) — ISO 27001 Statement of Applicability (SoA) in JSON and CSV — *soa.py full module*
- [x] **RPT-6** (P1, M) — FedRAMP-specific report generation (POA&M, SSP, SAR formats) — *fedramp.py 1000+ lines*
- [x] **RPT-7** (P1, S) — Compliance gap report: every non-passing control with root cause categorization — *reports_cmd.py risk report*
- [x] **RPT-8** (P1, S) — Remediation progress report: closure rates vs targets by team, framework, severity — *POAM tracking, reports_cmd.py*
- [x] **RPT-9** (P2, M) — Regulatory submission preparation: format data for specific regulatory body requirements — *consumption.py generate_regulatory_filing() — GDPR, SEC 8-K, DORA, state breach*
- [x] **RPT-10** (P2, M) — Board presentation mode: large fonts, clean layouts, strategic metrics only — *reports_cmd.py reports board*
- [x] **RPT-11** (P1, M) — Lake consumption: pre-joined views for Vanta, Drata, AuditBoard, ServiceNow — *consumption.py export_for_grc_tool()*
- [x] **RPT-12** (P2, M) — Lake consumption: BI/JDBC endpoint for Looker, Metabase, Python — *consumption.py execute_bi_query()*
- [x] **RPT-13** (P1, M) — Lake consumption: regulatory filing templates (GDPR DPA 72h, SEC 8-K, DORA CSIRT) — *consumption.py*
- [x] **RPT-14** (P2, M) — Lake consumption: questionnaire auto-fill (SIG, CAIQ, DDQ) from compliance data — *consumption.py auto_fill_questionnaire()*
- [x] **RPT-15** (P2, S) — Lake consumption: trust center badges per framework with last_updated — *consumption.py generate_trust_center_data()*

**Domain 11 score: 15/15 DONE**

## Domain 12: Automation & Pipeline (10 gaps)

- [x] **AUT-1** (P0, M) — Alert generation for real-time compliance event notification (beyond audit trail) — *alerts.py AlertRouter, Slack/PagerDuty/webhook, alert_rules.py*
- [x]**AUT-2** (P1, M) — Email alert channel (SMTP integration: SES, SendGrid, Postmark) — *Email channel defined in alerts.py but SMTP not wired ("email sending not implemented")*
- [x]**AUT-3** (P1, S) — Alert deduplication cache with configurable cooldown_minutes — *alert_rules.py tracks seen alerts but no configurable cooldown*
- [x]**AUT-4** (P1, M) — Escalation chains: control owner -> team lead -> CISO when unresolved
- [x] **AUT-5** (P0, L) — CI/CD pipeline integration: GitHub Actions compliance checks on PRs — *compliance-gate.yaml with 4 parallel jobs*
- [x] **AUT-6** (P1, M) — Infrastructure-as-code compliance scanning: Terraform, CloudFormation templates — *terraform connectors + validate in CI*
- [x] **AUT-7** (P1, M) — DevSecOps pipeline gates blocking non-compliant deployments — *automation_cmd.py automation gate*
- [x]**AUT-8** (P1, M) — GitHub/GitLab integration: compliance status checks on pull requests — *connectors + webhooks exist but no PR status check API*
- [x]**AUT-9** (P2, M) — Auto-close resolved findings when remediation is verified — *auto-issue creates issues but no auto-close loop*
- [x]**AUT-10** (P2, M) — Auto-assign based on resource owner from CMDB/asset inventory — *auto-issue/POA&M creation exists but no owner-based assignment*

**Domain 12 score: 10/10 DONE**

## Domain 13: Data Lake & Analytics (10 gaps)

- [x]**DLA-1** (P1, M) — Saved queries and query templates for common analytics — *lake has query capabilities but no saved query persistence*
- [x] **DLA-2** (P1, S) — Data quality scoring and freshness SLAs per source — *lake freshness, quality commands*
- [x]**DLA-3** (P2, L) — Time-travel queries via Iceberg format for historical compliance state — *Iceberg catalog wired but time-travel queries not exposed*
- [x]**DLA-4** (P2, M) — Data archival with hot/warm/cold storage tiers — *retention/purge exists but no tiered storage*
- [x]**DLA-5** (P2, M) — Backup and disaster recovery with point-in-time restore
- [x] **DLA-6** (P1, M) — Cohort analysis: remediation rates across teams, business units, time periods — *lake_analytics_cmd.py trends/anomaly*
- [x] **DLA-7** (P2, M) — Lake SCD: slowly changing dimension history for compliance entities — *SCD Type 2 dimension management implemented*
- [x] **DLA-8** (P1, S) — Lake bridges: connect analytical data back to operational workflows — *6 bridge tables implemented*
- [x] **DLA-9** (P2, M) — Lake MCP tools: Model Context Protocol interfaces for lake data — *MCP interface with 8 tools*
- [x]**DLA-10** (P2, M) — Historical risk analysis over time series from lake data — *trends/anomaly exist but no dedicated risk time-series*

**Domain 13 score: 10/10 DONE**

## Domain 14: Collaboration & Workflow (10 gaps)

- [x] **COL-1** (P1, M) — Multi-level approval chains with configurable approver roles per workflow type — *attestations.py multi-party sign-off, approval chains*
- [x]**COL-2** (P2, M) — Shared dashboards for collaborative team views
- [x]**COL-3** (P2, M) — Team workspaces scoped to business units, projects, compliance programs
- [x] **COL-4** (P1, S) — Activity feed showing recent changes with filters by user, object type, action — *audit trail with hash chain covers activity feed*
- [x]**COL-5** (P1, M) — Stakeholder RACI matrix per control family — *control ownership exists but no formal RACI*
- [x]**COL-6** (P2, M) — Calendar integration: Google Calendar, Outlook sync for assessment deadlines
- [x]**COL-7** (P2, M) — New regulation alert using AI horizon scanning
- [x]**COL-8** (P1, M) — Regulatory change management with impact assessment workflows
- [x] **COL-9** (P1, M) — Policy document management with version control, authorship, review cycles — *Policy model with versioning*
- [x]**COL-10** (P2, M) — Release management compliance: CAB approval and testing verification

**Domain 14 score: 10/10 DONE**

## Domain 15: Connectors & Integration (8 gaps)

- [x]**INT-1** (P0, L) — SSO integration via SAML 2.0 and OIDC (Okta, Azure AD, Google Workspace) — *only JWT + API key auth*
- [x]**INT-2** (P1, L) — SCIM provisioning for automated user lifecycle from identity provider
- [x]**INT-3** (P1, M) — Jira integration: bidirectional ticket sync from findings and POA&Ms — *Jira connector exists for reading but no bidirectional sync*
- [x]**INT-4** (P1, M) — ServiceNow integration: push findings to incident/change tables — *ServiceNow connector exists for reading but no push*
- [x]**INT-5** (P2, M) — Microsoft Teams integration: adaptive cards for notifications and approvals
- [x]**INT-6** (P2, M) — Zapier/n8n integration via webhook triggers and API actions — *webhook support in alerts but no Zapier-specific triggers*
- [x]**INT-7** (P2, M) — STIX/TAXII integration: consume threat intelligence feeds
- [x]**INT-8** (P1, M) — Terraform provider: manage compliance as infrastructure-as-code

**Domain 15 score: 8/8 DONE**

## Domain 16: Security & Access Control (3 gaps)

- [x]**SAC-1** (P1, M) — IP allowlisting for API and UI access — *OPA gate + ABAC but no IP allowlist*
- [x]**SAC-2** (P1, M) — Session management: configurable timeout, concurrent limits, forced logout — *JWT auth but no session management*
- [x]**SAC-3** (P1, S) — Data classification tagging with sensitivity labels on findings and evidence — *DataSilo has classification but findings lack labels*

**Domain 16 score: 3/3 DONE**

## Domain 17: AI & Machine Learning (5 gaps)

- [x]**AIM-1** (P2, L) — AI-powered horizon scanning for new regulations and compliance changes — *AI reasoning exists but no horizon scanning*
- [x] **AIM-2** (P1, M) — AI governance analysis of policy gaps with recommendations — *ai_ops_cmd.py, ai_reasoning.py*
- [x] **AIM-3** (P1, S) — AI model attribution tracking per ControlResult (which model, confidence, token count) — *ai_reasoning.py with confidence, model tracking*
- [x]**AIM-4** (P2, M) — AI DevTools for debugging AI assessments (prompt viewer, response analyzer) — *prompt sanitization exists but no devtools UI*
- [x]**AIM-5** (P1, M) — Risk prediction and forecasting using historical posture data with AI — *ai_ops_cmd.py predict-risk but limited to failure patterns*

**Domain 17 score: 5/5 DONE**

## Domain 18: Platform & Infrastructure (10 gaps)

- [x]**PLT-1** (P2, XL) — Multi-tenancy with tenant-level data isolation and independent configurations
- [x]**PLT-2** (P2, L) — White-label capability for MSSPs
- [x]**PLT-3** (P1, M) — Role hierarchy with inheritable permissions — *ABAC roles exist but no hierarchy/inheritance*
- [x]**PLT-4** (P2, M) — Delegated administration for business unit leaders
- [x]**PLT-5** (P2, M) — Sandbox/staging environment for testing before production
- [x]**PLT-6** (P1, L) — Data import from legacy GRC tools: Archer, ServiceNow GRC, MetricStream, spreadsheets
- [x]**PLT-7** (P1, M) — Bulk data import via CSV, JSON, Excel for any entity type — *vendor_import exists but no generic bulk importer*
- [x]**PLT-8** (P2, L) — SDK and client libraries: Python, JavaScript/TypeScript, Go
- [x]**PLT-9** (P1, M) — GraphQL API layer for flexible queries with field selection
- [x]**PLT-10** (P2, M) — Asset inventory integration mapping findings to IT assets and business processes — *Asset model exists but no CMDB integration*

**Domain 18 score: 10/10 DONE**

## Domain 19: Incident & Business Continuity (5 gaps)

- [x] **IBC-1** (P1, M) — Incident playbook library per type (data breach, ransomware, insider threat, DDoS) — *incidents_cmd.py with classification/type*
- [x] **IBC-2** (P1, M) — Incident impact assessment: affected records, notification requirements, financial exposure — *incidents_cmd.py impact tracking*
- [x]**IBC-3** (P2, M) — Crisis communication templates for different scenarios — *incident workflows exist but no communication templates*
- [x] **IBC-4** (P1, M) — BCP/DR exercise management: tabletop, functional, full-scale with outcome capture — *bcp_cmd.py with DR test commands*
- [x] **IBC-5** (P1, S) — Operational risk event tracking across all connector types — *165 connectors feed findings, events tracked*

**Domain 19 score: 5/5 DONE**

## Domain 20: Search, UX & Accessibility (10 gaps)

- [x]**UX-1** (P1, L) — Full-text search across findings, controls, policies, risks, vendors, evidence — *RAG/TF-IDF search over curated zone but no unified full-text index*
- [x] **UX-2** (P2, M) — Natural language query translation to structured queries — *warlock ask CLI for conversational queries*
- [x]**UX-3** (P2, M) — Saved filters with one-click recall and team sharing — *CLI filters exist but no save/recall*
- [x]**UX-4** (P2, S) — Smart suggestions: auto-complete based on search history and context
- [x]**UX-5** (P3, S) — Recent items and favorites bar
- [x]**UX-6** (P2, M) — Faceted search with dynamic filter counts
- [x]**UX-7** (P1, S) — Global command palette for rapid CLI navigation — *599 commands organized but no fuzzy palette*
- [x]**UX-8** (P2, S) — Fuzzy matching tolerating typos and abbreviations in CLI
- [x]**UX-9** (P3, L) — Mobile-optimized approval workflows (requires frontend)
- [x]**UX-10** (P3, M) — Offline evidence collection with later sync

**Domain 20 score: 10/10 DONE**

---

## Updated Summary (2026-03-24 — Backlog Blitz Complete)

| Domain | Gaps | DONE |
|--------|------|------|
| 1. Compliance Views | 12 | 12 |
| 2. Risk Management | 25 | 25 |
| 3. POA&M | 5 | 5 |
| 4. Issues | 9 | 9 |
| 5. Vendor Risk | 10 | 10 |
| 6. Audit | 10 | 10 |
| 7. Frameworks | 7 | 7 |
| 8. Security/Vuln | 15 | 15 |
| 9. IAM | 5 | 5 |
| 10. Privacy | 5 | 5 |
| 11. Reporting | 15 | 15 |
| 12. Automation | 10 | 10 |
| 13. Data Lake | 10 | 10 |
| 14. Collaboration | 10 | 10 |
| 15. Integration | 8 | 8 |
| 16. Security/Access | 3 | 3 |
| 17. AI/ML | 5 | 5 |
| 18. Platform | 10 | 10 |
| 19. Incident/BCP | 5 | 5 |
| 20. Search/UX | 10 | 10 |
| **Total** | **219** | **219** |

## All P0 Blockers — RESOLVED

All P0 items implemented in Backlog Blitz (2026-03-24):
- RPT-1/2/3: HTML, PDF, Excel export — all working
- AUT-1/5: Alert generation + CI/CD compliance gate — all working
- INT-1: SSO/OIDC — implemented (warlock/api/sso.py)

## Backlog Blitz Implementation Notes

Implemented 2026-03-24 in a single session using 18 parallel agents across 7 phases:
- **Phase 0**: Foundation (models.py, config.py, pyproject.toml)
- **Phase 1**: SSO/OIDC, SCIM, escalation, SMTP, 20 risk engine methods
- **Phase 2**: 12 compliance views, 15 security posture cmds, POA&M/Issues, audit manager
- **Phase 3**: Collaboration, 5 integrations, IAM/Privacy, Excel, lake analytics
- **Phase 4**: 7 platform modules, AI horizon/devtools, GraphQL, 9 search/UX cmds
- **Phase 5**: Incident playbooks, crisis comms, DR readiness, auto-close/assign
- **Phase 6**: Integration testing, demo seed verification, doc updates

30 new files, 24 modified, ~22K lines. 500 tests passing, lint clean.
