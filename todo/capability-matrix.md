# Warlock GRC Platform — Exhaustive Capability Matrix

Generated 2026-03-22 by 5 specialized GRC agents analyzing the full codebase.
1,417 raw capabilities identified, deduplicated and organized into 18 domains.

---

## Domain 1: Compliance Posture Views (82 capabilities)

1. View aggregate compliance posture score across all 14 frameworks with pass/fail/partial/not-assessed counts
2. View compliance posture for a single framework filtered by framework ID with drill-down to control families
3. View compliance posture by individual control ID with status breakdown, passing resources, and failing resources
4. View compliance posture by control family (AC, AU, CM, IA, SC, etc.) with per-family pass rates
5. View compliance posture by connector source system (AWS, Slack, Okta, CrowdStrike, etc.) — controls failing grouped by source
6. View compliance posture by resource type (ec2_instance, s3_bucket, iam_user, okta_user, etc.)
7. View compliance posture by specific resource ID (ARN, Azure resource ID, hostname)
8. View compliance posture by cloud account ID (AWS account, Azure subscription, GCP project)
9. View compliance posture by cloud region (us-east-1, westeurope, asia-east1, etc.)
10. View compliance posture by source type category (cloud, edr, scanner, siem, iam)
11. View compliance posture by provider vendor (AWS, Azure, GCP, CrowdStrike, Tenable, etc.)
12. View compliance posture by observation type (misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory)
13. View compliance posture by system profile / authorization boundary
14. View compliance posture by deployment model (cloud, on-premise, hybrid)
15. View compliance posture by service model (IaaS, PaaS, SaaS)
16. View compliance posture by FIPS 199 impact level (low, moderate, high)
17. View compliance posture by severity level (critical, high, medium, low, info)
18. View compliance posture by assessment method (assertion, AI reasoning, OPA policy)
19. View compliance posture by assignee / control owner
20. View compliance posture by business unit or organizational unit
21. Compliance heatmap by framework and control family showing status distribution and score percentage
22. Cross-framework compliance comparison showing pass rates side-by-side across all 14 frameworks
23. Framework coverage gap analysis showing controls with no connectors, no evidence, or no assertions mapped
24. Control coverage matrix showing connector sources vs controls (Y/N grid) per framework
25. Compliance score trending over 30/60/90/180/365-day windows with moving average
26. Week-over-week and month-over-month trend arrows on compliance scores
27. Compliance delta between two time periods showing which controls improved, degraded, or stayed same
28. Compliance regression detection alerting when previously passing controls start failing
29. Point-in-time compliance snapshot showing state at any historical date
30. Posture snapshot comparison between two specific dates
31. Control pass/fail rate analysis grouped by framework
32. Control effectiveness scores showing uptime percentage, MTTR hours, and drift count per control
33. Benchmark comparison of compliance posture against industry averages per framework
34. Peer benchmarking comparing organization posture against anonymized industry cohorts by sector and size
35. Compliance maturity model levels per framework (ad-hoc, repeatable, defined, managed, optimized)
36. Audit readiness score per framework estimating likelihood of passing external audit
37. Continuous authority to operate (cATO) dashboard showing real-time ATO health
38. Top-10 riskiest findings ranked by severity, age, blast radius, and framework impact count
39. Pareto analysis identifying the 20% of control families causing 80% of failures
40. Finding velocity metrics: new findings/day, closed findings/day, net finding growth rate
41. Finding age tracking with automatic escalation when findings exceed SLA thresholds
42. Finding deduplication and correlation linking same issue detected by multiple connectors
43. Side-by-side comparison of two pipeline runs showing new, resolved, and unchanged findings
44. Finding diff view showing what changed in a specific resource between consecutive scans
45. Resource-level compliance view showing all controls applicable to a specific resource
46. Account-level compliance view showing posture for a specific cloud account
47. Region-level compliance view showing findings grouped by geographic region
48. Multi-cloud compliance posture showing unified status across AWS, Azure, GCP
49. Cross-framework impact analysis: how remediating one finding affects pass rates across all 14 frameworks
50. Control inheritance analysis showing parent-child status propagation and override points
51. Common control provider identification: which systems provide evidence satisfying most frameworks
52. Multi-framework control deduplication: controls that satisfy multiple frameworks simultaneously
53. Framework overlap analysis: quantify how much work for one framework applies to another
54. Quick-win identification: low-effort fixes that improve compliance score the most
55. Compliance debt tracking: accumulated non-compliant control-days over time
56. Executive risk posture score with letter grade (A-F) and numeric score (0-100)
57. Board-ready compliance summary with pass/fail/partial across all active frameworks in single view
58. CISO dashboard with trend arrows, open findings, and control effectiveness metrics
59. Security operations dashboard showing findings by severity, active incidents, connector status
60. GRC program health dashboard showing overall program maturity indicators
61. KPI dashboard: compliance posture score, issue resolution rate, assessment counts vs targets
62. KRI dashboard: non-compliant percentage and critical issue count against thresholds with breach status
63. Live real-time compliance dashboard with auto-refresh (Rich Live display in terminal)
64. Continuous monitoring (ConMon) status report showing connector activity, posture snapshots, compliance score
65. SLA compliance report: issue resolution times against severity-based thresholds (critical 1d, high 7d, medium 30d, low 90d)
66. Attestation summary: percentage of controls assessed by assertions, AI, and auditor examination
67. Connector health report showing run status, event counts, error rates, timestamps per connector
68. Connector coverage map: which event types each connector collects
69. Connector gap detection: resource types with no connector coverage
70. Control assessment freshness: time since last assessment per control
71. AI confidence distribution across assessments with low-confidence flagging
72. Monitoring cadence check: controls assessed vs required frequency with staleness indicators
73. Evidence freshness overview per framework: controls with evidence within 7/30/90/365 days
74. Evidence staleness analysis identifying controls where evidence exceeds age threshold
75. Evidence sufficiency scores per control: volume, freshness, diversity, assertion coverage, gaps
76. Pipeline execution history with hash chain validation and timing metrics
77. Pipeline run statistics: raw events collected, findings normalized, controls mapped, results assessed
78. Data lake query interface for ad-hoc analytical queries using SQL or natural language
79. RAG-based natural language compliance queries ("What's our worst AWS finding?")
80. Platform health dashboard showing system performance, API latency, job status, connector sync health
81. Usage analytics showing platform adoption metrics (active users, features used, reports generated)
82. Forecasting: project when current remediation velocity will achieve target compliance levels

## Domain 2: Risk Quantification & Management (65 capabilities)

83. FAIR Monte Carlo simulation with PERT distributions and configurable iteration count (default 10,000)
84. Annualized Loss Expectancy (ALE) calculation per threat scenario
85. Value at Risk (VaR) at 90th, 95th, and 99th percentiles per scenario
86. Loss exceedance curve generation as (threshold, probability) tuples per scenario
87. Standard deviation, median, min, max ALE per scenario for uncertainty quantification
88. Portfolio-level risk aggregation across all scenarios within a framework (total ALE, total VaR-95)
89. Control effectiveness derivation from posture scores (0-100 mapped to 0.0-1.0)
90. Scenario catalog with pre-built PERT parameters for 25+ control families
91. Custom threat scenario definition with user-specified frequency and impact ranges
92. Posture-driven scenario auto-generation mapping controls to threats via family prefix
93. Inherent risk calculation: simulation with control_effectiveness=0.0 (unmitigated baseline)
94. Residual risk calculation: simulation with actual posture-derived effectiveness
95. Risk reduction ROI: inherent ALE minus residual ALE vs control implementation cost
96. What-if analysis: hypothetical ThreatScenario objects with modified effectiveness values
97. Risk trending over time by comparing sequential RiskAnalysis batches
98. Risk heatmap visualization plotting likelihood vs impact with color-coded severity
99. Risk appetite threshold definition per framework (max_ale, max_var95, max_high_findings)
100. Risk appetite breach detection with exceeded_by_pct for each threshold
101. Automatic framework scanning against risk appetites producing structured breach reports
102. Risk appetite configuration API for organization-specific overrides
103. Cost-of-noncompliance estimator projecting potential fines based on open findings
104. Risk acceptance workflow: create with description, level, requestor, expiry -> approval -> active -> expired/revoked
105. Risk acceptance with AO-level approval tracking and conditions documentation
106. Risk acceptance expiry management with automatic detection past expiry_date
107. Risk acceptance expiring-soon alerts within configurable N-day window
108. Risk acceptance auto-re-evaluation triggers: severity_change, new_finding, time_elapsed
109. Risk acceptance trigger evaluation engine scanning all active acceptances
110. Residual risk level tracking on acceptance records
111. Compensating control lifecycle: proposed -> approved -> active -> expired/revoked
112. Compensating control effectiveness scoring (0-100)
113. Compensating control expiry date tracking with automatic invalidation
114. Compensating control review frequency configuration with last_reviewed tracking
115. Compensating control evidence references as structured JSON
116. Compensating control linkage to POA&Ms
117. Compensating control influence on posture scoring
118. Risk register via RiskAnalysis table with full scenario metadata
119. Risk register export with POA&M cross-references
120. Risk committee reporting via structured AppetiteCheckResult objects
121. Risk culture metrics through posture trending, drift detection, MTTR, uptime tracking
122. Risk ownership tracking through SystemProfile, POA&M, RiskAcceptance, Issue actor fields
123. Organizational risk posture aggregation rolling up control-level to framework-level and system-level
124. Framework-specific risk appetite defaults for 10 frameworks
125. Cross-framework risk correlation through UCF crosswalk mappings
126. Risk scenario library: ransomware, data breach, cloud outage, supply chain compromise
127. Risk interconnection mapping showing dependencies and cascade effects between risks
128. Risk aggregation rolling up individual risks to business unit, domain, and enterprise levels
129. Emerging risk identification using AI to scan threat intelligence and regulatory feeds
130. Quantitative risk analysis producing loss exceedance curves and value-at-risk metrics
131. Risk lifecycle management: identification -> assessment -> treatment -> monitoring -> closure
132. Monte Carlo simulation result caching using SHA-256 fingerprinting with thread-safe LRU cache
133. Risk cache pre-computation (weekly schedule) pre-warming results for all active frameworks
134. Risk analysis persistence with full breakdown per run
135. Historical risk analysis querying by framework and timestamp for trend analysis
136. Thread-safe simulation execution for concurrent API and CLI requests
137. PERT distribution sampling via numpy Beta with stdlib triangular fallback
138. Composite risk scoring weighting frequency reduction by control effectiveness
139. Framework-specific scenarios: GDPR (20M EUR fines), HIPAA (PHI breach), PCI DSS (payment compromise), SEC Cyber (disclosure failure)
140. Supply chain concentration analysis counting control dependencies per vendor
141. Vendor blast radius computation: all systems, frameworks, controls affected if vendor fails
142. Fourth-party risk visibility through concentration analysis and blast radius
143. Risk treatment cost-benefit analysis: simulation with/without proposed control
144. Risk appetite analysis via dedicated assessor module
145. Impact propagation across dependent systems via propagation assessor
146. Compliance simulation scenarios via simulation assessor
147. Board-level risk dashboard: total_mean_ale, total_var_95, scenario count, high-risk count, appetite breach status

## Domain 3: POA&M Management (25 capabilities)

148. POA&M auto-creation from non-compliant control results with deduplication check
149. POA&M validated status transitions: draft->open->in_progress->remediated->verified->completed (risk_accepted/cancelled from any state)
150. POA&M extension workflow with mandatory justification, approved_by, delay_count increment, append-only delay_justifications
151. POA&M extension date validation rejecting past or current dates
152. POA&M overdue detection with timezone-safe ensure_aware() comparison
153. POA&M listing with multi-dimensional filtering (framework, status, overdue flag)
154. POA&M milestone tracking via JSON array of {description, due_date, completed_date, status}
155. POA&M severity and risk_level derived from originating control result
156. POA&M vendor dependency documentation
157. POA&M resource requirements documentation
158. POA&M system profile scoping for multi-system environments
159. POA&M actor audit trail: created_by, updated_by, approved_by with timestamps
160. POA&M rich CLI display: ID, framework, control, severity, status, due date, delay count, weakness
161. POA&M remediation guidance: weakness, manual steps, console path, CLI commands, evidence instructions
162. POA&M to issue linkage via Issue.poam_id foreign key
163. POA&M comment workflow via linked issue or append-only delay_justifications
164. POA&M AI-enhanced remediation guidance via --ai flag
165. POA&M interactive AI reasoning via --ask flag with entity context
166. POA&M scheduled completion tracking with actual_completion timestamp
167. POA&M dashboard integration for board-level reporting on open/overdue/delayed counts
168. POA&M aging report showing delay counts, scheduled vs actual completion, justifications
169. POA&M cost tracking and resource allocation documentation
170. POA&M dependencies between items
171. POA&M escalation triggers for overdue items
172. POA&M bulk operations: batch update status, assignment, priority

## Domain 4: Issue Management (30 capabilities)

173. Issue auto-creation from non-compliant control results with deduplication per (framework, control_id)
174. Issue lifecycle state machine: open->assigned->in_progress->remediated->verified->closed (risk_accepted from any open state, reopen from closed)
175. Issue auto-assignment with assigned_to, assigned_by, assigned_at tracking
176. Issue risk acceptance with owner, justification (required), configurable expiry_days
177. Issue evidence attachment with description, URL, timestamp audit trail
178. Issue comment system with typed comments (comment, status_change, assignment, evidence)
179. Issue summary aggregation: counts by status, by priority, overdue count
180. Issue priority mapping from finding severity: critical->critical, high->high, medium->medium, low/info->low
181. Issue AI-powered analysis via --ask flag for natural language questions about listed issues
182. Issue-to-POA&M linkage for formal remediation plans
183. Issue-to-compensating-control linkage
184. Issue-to-risk-acceptance linkage
185. Issue filtering by status, priority, framework, assignee, date range, custom tags
186. Issue bulk operations: bulk assign, bulk close, bulk tag, bulk change severity, bulk add to POA&M
187. Issue SLA enforcement tracking remediation timelines by severity with auto-escalation
188. Issue remediation guidance with AI-generated fix recommendations
189. Issue timeline view showing complete lifecycle with timestamps
190. Root cause analysis grouping related findings under common root cause
191. Issue comment threading with @mention notifications
192. Issue delegation and out-of-office routing
193. Issue remediation velocity tracking: average time from creation to resolution by priority
194. Watch list allowing subscription to status changes on specific issues
195. Task assignment with due dates, priority levels, assignee selection
196. Issue-to-finding linkage showing all findings contributing to an issue
197. Finding-to-issue linkage showing all incidents linked to a finding
198. Cross-reference: all findings mapped to a specific control
199. Cross-reference: all controls mapped to a finding with source, severity, mapping method
200. Blast radius analysis for a finding: how many controls, frameworks, systems affected
201. Orphan finding detection: findings with no control mapping
202. Orphan control detection: controls with mappings but no assessment results

## Domain 5: Vendor Risk Management (35 capabilities)

203. Vendor risk composite scoring: weighted 0-100 across criticality, data sensitivity, assessment currency, security posture, SLA compliance
204. Vendor criticality tiering with inverse scoring (critical vendors = higher risk score)
205. Vendor data sensitivity scoring with inverse weighting
206. Vendor assessment currency scoring with linear degradation from expected frequency
207. Vendor security posture scoring from SecurityScorecard connector data
208. Vendor SLA compliance scoring: uptime_pct, response_time_met, breach_notification_met
209. Vendor risk level classification: low (80+), medium (60-79), high (40-59), critical (<40)
210. Automated vendor recommendation generation for overdue assessments, weak posture, critical vendors
211. Vendor profile auto-construction from SecurityScorecard findings
212. Vendor risk monitoring auto-creating Finding rows for high-risk vendors feeding back into pipeline
213. Supply chain concentration analysis: control dependency counts per vendor
214. Vendor blast radius: all systems, frameworks, controls affected if vendor fails
215. Fourth-party risk visibility through transitive dependency analysis
216. Vendor exit planning support through blast radius scope analysis
217. Vendor incident notification tracking via SLA metrics
218. Vendor assessment frequency configuration (default 90-day cadence)
219. Vendor risk scoring weight customization
220. Vendor issue tracking with structured issue list per vendor
221. Vendor risk factor breakdown: individual SecurityScorecard factor scores
222. Vendor risk finding creation with full lineage back to synthetic raw events
223. Vendor security questionnaire management (SIG, SIG Lite, DDQ, CAIQ, custom templates)
224. Questionnaire completion tracking with reminders and overdue escalation
225. Questionnaire score computation from responses (0-100)
226. AI auto-suggest answers for questionnaire responses with confidence scores
227. Questionnaire lifecycle: draft->sent->in_progress->completed->reviewed->accepted/rejected
228. Questionnaire template management with control mappings per question
229. Vendor contract management: agreement terms, security obligations, audit rights, renewal dates
230. Vendor continuous monitoring integrating external risk rating feeds
231. Vendor access inventory showing which systems/data each vendor accesses
232. Vendor offboarding checklist: access revocation, data return/destruction, final assessment
233. Vendor compliance mapping: which controls each vendor's services satisfy
234. Vendor onboarding due diligence workflow
235. Vendor lifecycle management: onboarding -> monitoring -> offboarding
236. Vendor risk register with tiering by data access and business impact
237. Vendor portfolio risk report listing all vendors with scores, levels, recommendations

## Domain 6: Audit Management (45 capabilities)

238. Audit engagement creation with framework, name, auditor (name + firm), observation period dates
239. Audit engagement listing filtered by status (active/completed/archived) and framework
240. Audit engagement detail: in-scope controls, excluded controls, auditor info, comment threads
241. Engagement progress summary: control result breakdown, open vs resolved comments
242. Audit scoping: define in-scope and excluded controls per audit period
243. Evidence binder package generation per engagement to specified directory
244. Evidence binder ZIP organized by control_family/control_id with evidence.json, poams.json, compensating.json, acceptances.json
245. Evidence binder path traversal prevention via regex sanitization
246. Import audit findings from CSV (control_id, framework, status, severity, notes)
247. Corrective action comments listing filtered by resolution status (open/resolved)
248. Audit pre-flight checklist: evidence freshness, coverage percentage, open POAMs, stale evidence, attestations
249. Audit readiness score (0-100) with weighted breakdown: compliance 50%, coverage 30%, freshness 20%, POAM penalty, attestation bonus
250. Pre-audit report generation in markdown and JSON formats
251. Audit simulation projecting posture at future date: stale controls, overdue POA&Ms, expiring acceptances, at-risk controls
252. Audit simulation projected coverage percentage calculation
253. Audit simulation AI readiness assessment with recommended actions
254. External auditor assignment via AuditorEngagementAssignment
255. External auditor magic-link authentication
256. Auditor-practitioner collaboration via threaded AuditComment model
257. Comment resolution status tracking per engagement
258. Separation of duties enforcement: preparer, reviewer, approver must differ
259. Attestation lifecycle: draft->submitted->reviewed->approved->rejected
260. Control result examination tracking: examined_at, examined_by
261. Audit universe definition and risk-based audit planning
262. Audit workpaper management with structured templates and reviewer sign-off
263. Audit finding tracking from draft through management response to closure verification
264. External audit coordination portal with secure read-only access
265. Continuous auditing capability using automated tests between formal engagements
266. Audit report generation with customizable templates
267. Sampling methodology: statistically significant sample selection from large control populations
268. Audit observation recording with severity, affected controls, management response
269. Audit finding escalation: finding -> issue -> POA&M with linked remediation
270. Audit schedule recommendation based on monitoring frequencies and last assessment dates
271. Audit comment thread management with resolution tracking
272. Evidence request workflow: auditor requests -> practitioner uploads -> auditor verifies
273. Evidence request listing filtered by status (pending/fulfilled/overdue)
274. Evidence request fulfillment by linking to control result IDs
275. Evidence review queue listing evidence awaiting auditor review
276. Evidence freshness report per framework: controls with evidence within 7/30/90/365 days
277. End-to-end finding trace: raw event -> finding -> control mappings -> control results -> evidence IDs -> audit trail
278. Evidence chain of custody with hash verification at each stage
279. Evidence validity rules: minimum freshness, required artifact types, acceptance criteria per control
280. Hash-chain audit trail integrity verification checking SHA-256 chain continuity
281. Digital signature and attestation on evidence submissions and policy acknowledgments
282. Compliance certification package assembly: policies, evidence, test results, attestations

## Domain 7: Framework Operations (40 capabilities)

283. 14-framework control catalog with 1,996 total controls
284. List all frameworks showing ID, display name, family count, control count
285. Show framework detail: families, controls, event types
286. List controls for a framework filtered by family with check counts and event type counts
287. Compare two frameworks: shared controls, unique controls, shared families
288. Show crosswalk mappings from source to target frameworks with mapping method
289. Show control coverage per framework: controls with DB results vs uncovered
290. Show compliance gaps per framework: controls with no compliant findings
291. Framework aggregate statistics: control counts, result counts, compliance breakdown
292. Export framework definition to JSON or YAML
293. List event types referenced by a framework's controls
294. List connectors relevant to a framework by cross-referencing event types
295. Monitoring frequency calendar: controls grouped by daily/weekly/monthly/quarterly/annual
296. Control inheritance report filtered by cloud provider
297. List NIST control baselines (Low/Moderate/High) with descriptions and control counts
298. Show controls in a specific baseline
299. Apply baseline with dry-run preview
300. List inherited control sets by provider and inheritance type
301. Compare framework versions: added, removed, modified, unchanged controls (framework-diff)
302. Framework YAML v2 dict-based structure with explicit control definitions, event_type mappings, monitoring frequencies
303. Framework crosswalk YAML for transitive control mapping with confidence decay
304. Crosswalk path tracking preserving transitive mapping chain for audit transparency
305. UCF-first control architecture: assess-once-map-to-N-frameworks
306. Control mapping pipeline: explicit, resource_rule, keyword, crosswalk, semantic (embedding-based)
307. Mapping confidence scoring differentiating reliability across methods
308. Semantic control mapping via embedding providers for vector similarity matching
309. Assertion propagation via crosswalks: NIST AC-2 pass cascades to SOC2 CC6.1
310. Family-level default assertions providing baseline coverage for every control family
311. Baseline and overlay management supporting NIST Low/Moderate/High with organization-specific overlays
312. Inherited controls reference documenting provider-inheritable controls
313. Shared responsibility matrix generation: customer vs provider responsibilities per control
314. Baseline tailoring: adjust standard baseline by adding/removing controls per system
315. Control implementation status tracking: planned/implemented/partially-implemented/not-implemented per system
316. Custom framework definition: import proprietary frameworks in YAML or OSCAL format
317. Framework versioning workflow handling version transitions without losing historical data
318. Cross-framework common findings: findings mapping to multiple frameworks with minimum count filter
319. Control crosswalk management maintaining mapping graph (1,843+ edges across 14 frameworks)
320. Control gap analysis: controls with no assertions, no evidence, no test coverage
321. Control test execution and result recording with pass/fail/partial
322. Control test scheduling at configurable frequencies

## Domain 8: Security Posture & Vulnerability Management (55 capabilities)

323. Aggregate security posture score across all systems, frameworks, connectors
324. Vulnerability scan aggregation from multiple scanners (Tenable, Qualys, Nessus, Rapid7, CrowdStrike Spotlight)
325. Vulnerability deduplication across scanners
326. Vulnerability prioritization by CVSS, exploitability, asset criticality, exposure context
327. Vulnerability remediation status tracking through issue lifecycle
328. Vulnerability remediation SLA compliance by severity tier
329. Vulnerability exception management with risk acceptance workflow
330. False positive handling with documented justification and review
331. Vulnerability aging: days open by severity
332. Vulnerability trending by severity over 30/60/90/180/365 days
333. Cross-scanner vulnerability correlation (same host detected by multiple tools)
334. Vulnerability-to-control mapping across all 14 frameworks
335. Vulnerability count by resource type, cloud account, density per asset
336. Vulnerability remediation reports with SLA metrics
337. MTTR/MTTD tracking by vulnerability severity
338. Vulnerability backlog burndown tracking
339. CIS benchmark compliance via OPA/Rego policies
340. Configuration baseline comparison against hardening benchmarks (NIST Low/Mod/High)
341. Configuration drift detection using ComplianceDrift model
342. Drift correlation with change events (CloudTrail, GitHub, ServiceNow, Terraform)
343. Drift direction tracking (improved vs degraded) with posture score delta
344. Auto-generated remediation steps for misconfiguration findings
345. Configuration policy enforcement via OPA gate (fail-closed)
346. Configuration waiver management through compensating control workflow
347. Configuration compliance by CIS benchmark section
348. Configuration compliance by cloud service (EC2, S3, IAM, VPC, RDS)
349. Encryption status tracking across data silos (at-rest, in-transit)
350. Logging coverage analysis (access_logging_enabled)
351. Backup status tracking across data silos
352. Cloud misconfigurations by service: AWS, Azure, GCP specific views
353. Cross-cloud comparison of equivalent security controls
354. Security group / NSG / firewall rule analysis
355. Network exposure analysis from cloud connector findings
356. Public-facing resource tracking across all cloud accounts
357. Cross-account access and trust relationship analysis
358. Cloud resource inventory from Axonius, RunZero, Orca, Wiz
359. CSPM findings from Prisma, Lacework, Ermetic, Orca, Wiz
360. Kubernetes cluster security posture tracking
361. Container vulnerability analysis from Snyk, Trivy, Aqua, Chainguard
362. Software supply chain security from FOSSA, Socket.dev, Syft/Grype
363. SAST findings from Semgrep, SonarQube, Checkmarx, Veracode
364. IOC correlation from CrowdStrike, SentinelOne, Defender
365. Threat actor TTP mapping to control coverage gaps
366. Attack surface analysis from SecurityScorecard, BitSight
367. Exposure scoring from Vulcan, BitSight, SecurityScorecard
368. GuardDuty alert correlation with IAM and network findings
369. External attack surface changes over time
370. SIEM alert correlation (Splunk, Elastic, Sumo Logic, LogRhythm, Sentinel, Datadog)
371. Incident-to-finding-to-control linkage
372. MTTR/MTTD by incident severity
373. Security KPI dashboard from posture snapshots, drift counts, MTTR
374. Patch compliance tracking against SLA timelines per asset criticality
375. Endpoint compliance: device encryption, OS version, antivirus, MDM enrollment (Jamf, Intune, Kandji)
376. Network segmentation compliance verification
377. Certificate lifecycle management (Venafi, DigiCert, AWS ACM)

## Domain 9: Identity & Access Management (25 capabilities)

378. Periodic access review using Personnel model (last_access_review, access_review_status)
379. Orphaned account detection: terminated HR status but active IdP
380. Excessive permissions analysis from IAM findings (AWS IAM, Azure RBAC, GCP IAM)
381. MFA coverage tracking across personnel (mfa_enabled field)
382. Privilege analysis via Okta, Entra ID, OneLogin, JumpCloud, Ping Identity data
383. Separation of duties (SoD) violation detection using SoD CLI module
384. Personnel risk scores combining HR, IdP, training, access review data
385. HR-IdP cross-referencing (Workday, BambooHR, ADP, Gusto, Rippling, SAP, Paylocity, UKG)
386. Employee type distribution and access level tracking (employee, contractor, vendor, intern)
387. Stale account detection (no login within policy window)
388. Background check status and completion tracking
389. NDA and agreement signing status
390. Access review completion rates by department
391. IdP group membership changes over time
392. Role-to-permission mapping from SailPoint, CyberArk data
393. Phishing simulation scores from KnowBe4
394. Security awareness training compliance (current, overdue, not_enrolled)
395. Training completion history by campaign
396. Access review campaign creation with scope, reviewer, deadline
397. Access review campaign listing filtered by status with progress tracking
398. Access review certification: record decision (appropriate/revoke) per user with justification
399. Access review revocation recording with reason
400. Access review report generation (markdown/JSON)
401. Overdue access review campaign listing
402. Cloud entitlement management: excessive permissions detection with least-privilege recommendations

## Domain 10: Privacy & Data Governance (30 capabilities)

403. GDPR Article 15 (Right of Access): export all personal data across 7 entity tables
404. GDPR Article 17 (Right to Erasure): HMAC-based deterministic anonymization preserving referential integrity
405. GDPR erasure cascade across 8 entity types with idempotent operation
406. GDPR anonymization using HMAC(field_name + record_id, secret) for deterministic tokens
407. PII detection flag on Finding model (pii_detected boolean)
408. Data retention policy enforcement with framework-specific periods (HIPAA=6yr, FedRAMP/NIST/ISO=3yr, SOC2/PCI=1yr)
409. Retention manager using longest-applicable-framework retention for multi-framework records
410. Retention purge respecting legal holds (scoped and global)
411. Retention purge transactional order respecting FK constraints
412. Retention purge freeze capability (WLK_RETENTION_PURGE_FROZEN)
413. Retention dry_run mode counting purgeable records without deleting
414. Legal hold creation with reason, dates, actor attribution
415. Legal hold deactivation (soft delete) preserving record
416. Legal hold listing with active-only filter
417. Retention report: records by age bucket, purgeable count, active holds, framework policies
418. Data silo discovery and classification (S3, RDS, SharePoint, Snowflake, GitHub repos)
419. Sensitive data classification: public, internal, confidential, restricted
420. PII/PHI/PCI/credential detection in discovered silos
421. Data silo protection status tracking: encryption, logging, backup
422. Data silo-to-framework mapping (HIPAA, GDPR, PCI DSS)
423. Data silo ownership tracking by team
424. DSAR management: access, deletion, portability, rectification requests with SLA monitoring
425. Privacy breach management: severity, scope, regulatory notification deadline tracking
426. Cross-border data transfer documentation: SCCs, BCRs, adequacy decisions
427. Data Protection Impact Assessment (DPIA) workflow
428. Record of Processing Activities (ROPA) generation
429. Privacy rights request management with deadline tracking
430. Cookie consent and tracking transparency documentation
431. Privacy impact assessment (PIA) management with templates
432. Data processing activity register documenting purposes, legal bases, categories, retention

## Domain 11: Reporting & Export (45 capabilities)

433. Executive compliance posture summary report with posture score, counts, issues, findings
434. Executive report in JSON format for API consumption
435. Detailed per-control compliance status report per framework
436. Compliance posture trend report from snapshots over configurable lookback
437. Top open risk items report: issues and POA&Ms by severity per framework
438. Board-level GRC summary: overall posture, critical issues, tracked POA&Ms
439. Executive briefing auto-generation with AI narrative
440. OSCAL Assessment Results export in JSON format
441. OSCAL System Security Plan (SSP) export
442. OSCAL POA&M export
443. OSCAL Component Definition export
444. AI-generated framework-aware narratives for SSP and POA&M (adapts to NIST/ISO/SOC2)
445. FedRAMP-specific report generation
446. FedRAMP continuous monitoring reports
447. SOC 2 Type II report with management assertion, criteria, test procedures, results, exceptions
448. SOC 2 AI narrative generation for control descriptions
449. ISO 27001 Statement of Applicability (SoA) in JSON and CSV
450. ISO 27001 SoA with implementation status from ControlResult data
451. Generic markdown compliance report with summary, per-control details, exceptions, remediation
452. HTML compliance report with print CSS, status color coding, branding
453. PDF compliance report via weasyprint with fallback
454. Temporal evidence packager: all findings/results within date range for framework
455. Temporal evidence gap identification (controls with no evidence in audit period)
456. Temporal evidence per-control metadata: finding count, result count, status distribution
457. Temporal evidence export in JSON and CSV
458. Alert generation for real-time compliance event notification
459. Scheduled report delivery (daily/weekly/monthly/quarterly) with email configuration
460. Report generation history tracking from audit log
461. Custom report templates with organization branding
462. Interactive drill-down reports: summary metrics -> underlying detail
463. Multi-format export: PDF, Excel, CSV, JSON, OSCAL
464. Export to Excel/CSV for any tabular data in the platform
465. Export to PDF for individual findings, control families, framework summaries
466. Compliance gap report: every non-passing control with root cause categorization
467. Finding aging report: open findings by age bucket with SLA tracking
468. Remediation progress report: closure rates vs targets by team, framework, severity
469. Executive risk report: top risks, treatment status, residual exposure in board language
470. User access review report listing all permissions for periodic certification
471. Regulatory submission preparation: format data for specific regulatory body requirements
472. Board presentation mode: large fonts, clean layouts, strategic metrics only
473. Lake consumption: pre-joined views for Vanta, Drata, AuditBoard, ServiceNow
474. Lake consumption: BI/JDBC endpoint for Looker, Metabase, Python
475. Lake consumption: regulatory filing templates (GDPR DPA 72h, SEC 8-K 4 business days, DORA CSIRT)
476. Lake consumption: questionnaire auto-fill (SIG, CAIQ, DDQ) from compliance data
477. Lake consumption: trust center badges per framework with last_updated timestamp

## Domain 12: Automation & Pipeline (50 capabilities)

478. Pipeline orchestrator: 4-stage flow (Ingest -> Normalize -> Map -> Assess)
479. Pipeline Stage 5: OPA compliance evaluation in per-framework batches
480. Pipeline concurrency lock: pg_advisory_lock (Postgres) or fcntl file lock (SQLite) with stale PID detection
481. Pipeline PgBouncer compatibility with transaction-level advisory locks
482. Pipeline all-or-nothing transaction rollback on unhandled exceptions
483. Pipeline per-connector batch flush with session.expunge_all() for memory management
484. Pipeline run_id correlation via contextvars for log tracing
485. Pipeline EventBus publishing at each stage transition
486. Scheduler: 7 independent schedules (pipeline_collect hourly, posture_snapshot daily, cadence_check hourly, retention_purge weekly, ccm_stale_check hourly, risk_reeval 6h, risk_cache weekly)
487. Scheduler ThreadPoolExecutor with 4 workers, non-blocking
488. Scheduler prevents overlapping executions per schedule
489. Scheduler per-schedule state tracking: last_run, run_count, last_error, next_run, enabled
490. EventBus in-process synchronous pub/sub with subscribe, subscribe_all, publish
491. EventBus auto-registration: WebhookSubscriber, SlackNotifier, PagerDutyNotifier, JiraNotifier, ServiceNowNotifier, AuditEventSubscriber
492. RedisStreamBus: Redis Streams with consumer groups (XREADGROUP/XACK) for persistent at-least-once delivery
493. KafkaBus: confluent-kafka and kafka-python support with wildcard topic broadcasting
494. SQSBus: per-event-type queues with configurable retry, visibility timeout, retention
495. NATSBus: JetStream for lightweight durable messaging
496. Queue backend factory from environment variables with graceful fallback to in-memory
497. Continuous Control Monitoring (CCM): watch evidence changes, trigger targeted reassessment without full pipeline
498. CCM control-evidence map from ControlMapper explicit rules
499. CCM on_finding_created handler for real-time reassessment
500. CCM stale control detection against monitoring frequency thresholds
501. Auto-create issues from non-compliant findings
502. Auto-assign based on resource owner
503. Auto-escalate overdue POA&Ms
504. Auto-close resolved findings
505. Notification rules: configurable triggers for status changes, threshold breaches, SLA warnings
506. Webhook-based notifications with HMAC-SHA256 request signing
507. Webhook retry with exponential backoff (1s, 2s, 4s) up to 3 attempts
508. Slack Block Kit formatted alerts with status emoji, scores, findings, evidence freshness
509. PagerDuty Events API v2: severity mapping, dedup_key, component/group classification
510. Email alert channel (SMTP integration: SES, SendGrid, Postmark)
511. Alert deduplication cache with configurable cooldown_minutes (default 60)
512. Alert routing: posture evaluation against configurable thresholds per framework
513. Alert suppression rules for known-noisy connectors or accepted-risk findings
514. Escalation chains: control owner -> team lead -> CISO when unresolved
515. Pipeline loader: 150+ connector modules, 150+ normalizer modules via dynamic importlib
516. Pipeline loader: 14 framework YAML configs and crosswalks with LRU-cached parsing
517. Pipeline loader: ConnectorRegistry with enable/disable flags per provider
518. Pipeline loader: AssertionPropagator registration for cross-framework assertion cascade
519. Pipeline loader: semantic mapper attachment when embedding_provider configured
520. Pipeline loader: AI reasoner initialization from configured provider
521. Pipeline loader: OPA evaluator initialization with fail_mode configuration
522. Pipeline loader: lake writer EventBus subscriber when lake_enabled
523. Automation rules for rule-based workflow triggers on pipeline events
524. CI/CD pipeline integration: GitHub Actions, GitLab CI, Jenkins, CircleCI for shift-left compliance
525. Infrastructure-as-code compliance scanning: Terraform, CloudFormation, Pulumi templates
526. DevSecOps pipeline gates blocking non-compliant deployments
527. GitHub/GitLab integration: compliance status checks on pull requests

## Domain 13: Data Lake & Analytics (40 capabilities)

528. Lake writer subscribes to EventBus, flushes Parquet files after pipeline success
529. LakeQueryEngine: embedded DuckDB for analytical queries over Parquet/Iceberg
530. LakeQueryEngine: S3/HTTP reads via httpfs extension for cloud object storage
531. LakeQueryEngine: results as dicts or PyArrow Tables
532. Lake RAG: TF-IDF cosine similarity search over compliance documents (no API key required)
533. Lake RAG: upgradeable to OpenAI/Anthropic embeddings for semantic search
534. Lake aggregations: materialized agg_framework_posture and agg_control_family_posture tables
535. Lake batch_assessor: majority voting across assessments per (framework, control_id)
536. Lake maintenance: compact() merges small Parquet files targeting 256MB
537. Lake maintenance: expire_snapshots() with per-zone retention (raw=7d, enrichment=30d, curated=365d)
538. Lake maintenance: cleanup_orphans() removes empty directories
539. Lake maintenance: expire_snapshots_safe() checks legal holds before expiring
540. Lake maintenance: run_all_maintenance() sequential compaction, expiry, orphan cleanup
541. Lake SCD: slowly changing dimension history for compliance entities
542. Lake shadow writes: shadow copies of OLTP data for analytical queries
543. Lake reconciliation: validate OLTP vs lake consistency
544. Lake backfill: populate lake from historical OLTP data
545. Lake OLTP thin bridge: lightweight OLTP access from lake
546. Lake domains module: domain service integration with lake analytics
547. Lake MCP tools: Model Context Protocol interfaces for lake data
548. Lake storage module: Parquet I/O and zone directory structure
549. Lake schema module: PyArrow schemas for lake tables
550. Lake zones: raw/enrichment/curated zone lifecycle management
551. Lake catalog: metadata registry for lake tables
552. Lake readers: typed reader interfaces for lake data
553. Ad-hoc SQL queries across historical pipeline runs
554. Natural language compliance queries via RAG
555. Saved queries and query templates
556. Data lineage tracking through pipeline stages
557. Data quality scoring and freshness SLAs
558. Anomaly detection using Isolation Forest with Z-score/IQR fallback
559. Time-travel queries via Iceberg format for historical compliance state
560. Iceberg table management for versioned compliance snapshots
561. Lake ask module: natural language query interface
562. Lake bridges: connect analytical data back to operational workflows
563. Data archival with hot/warm/cold storage tiers
564. Backup and disaster recovery with point-in-time restore
565. Historical risk analysis over time series
566. Correlated timeline of findings, incidents, change events over configurable lookback
567. Cohort analysis: remediation rates across teams, business units, connectors, time periods

## Domain 14: Collaboration & Workflow (30 capabilities)

568. Review and approval workflows for POA&Ms, risk acceptances, compensating controls, policy exceptions
569. Multi-level approval chains with configurable approver roles per workflow type
570. Comment and discussion threads on any GRC object with @mention notifications
571. Shared dashboards for collaborative team views
572. Team workspaces scoped to business units, projects, compliance programs
573. Activity feed showing recent changes with filters by user, object type, action
574. Audit engagement collaboration portal for external auditors
575. Stakeholder RACI matrix per control family
576. Compliance calendar: assessment schedules, audit dates, certifications, policy reviews, training deadlines
577. Calendar integration: Google Calendar, Outlook sync for assessment deadlines
578. Regulatory deadline tracker with countdown timers
579. New regulation alert using AI horizon scanning
580. Compliance program management grouping frameworks, assessments, activities with progress tracking
581. Regulatory change management with impact assessment workflows
582. Policy document management with version control, authorship, review cycles, electronic signature
583. Policy attestation campaigns with acknowledgment tracking and reminders
584. Policy exception management with justification, approval, expiration, compensating controls
585. Policy mapping to controls showing satisfaction across frameworks
586. Policy lifecycle: draft -> review -> approved -> published -> retired
587. Policy coverage analysis per framework with RAG-based or keyword heuristic matching
588. AI governance analysis of policy gaps with recommendations
589. Change management request creation with type, description, impact assessment
590. Change management approval workflow
591. Change event tracking correlated with compliance drift
592. Release management compliance: CAB approval and testing verification
593. Training record management: assign, track, report on compliance training
594. Training compliance status by department or role
595. Business continuity plan management with testing schedules and version control
596. Business impact analysis: RTO and RPO calculation per business process
597. DR plan management with recovery procedures, contact lists, testing documentation

## Domain 15: Connectors & Integration (35 capabilities)

598. 82 source connectors across cloud, EDR, IAM, scanners, SIEM, HRIS, ITSM, DLP, backup, MDM, GRC, email, code, network, observability, training
599. 82 matching normalizers converting raw data to standardized FindingData
600. Connector health monitoring: success/failure/partial rates, event counts, error details, timestamps
601. Connector configuration: enable/disable per provider, polling intervals
602. Connector run tracking: status (running, success, partial, error), duration, error details
603. SSO integration via SAML 2.0 and OIDC (Okta, Azure AD, Google Workspace, PingFederate)
604. SCIM provisioning for automated user lifecycle from identity provider
605. REST API with OpenAPI specification covering all platform objects
606. Webhook subscriptions for real-time event notifications
607. Jira integration: bidirectional ticket sync from findings and POA&Ms
608. ServiceNow integration: push findings to incident/change tables, pull CMDB asset data
609. Slack integration: slash commands and bot notifications
610. Microsoft Teams integration: adaptive cards for notifications and approvals
611. PagerDuty integration: critical finding escalation
612. Zapier/n8n integration via webhook triggers and API actions
613. Splunk/Elastic integration: forward findings and audit trail to SIEM
614. STIX/TAXII integration: consume threat intelligence feeds
615. Email gateway integration: ingest compliance-related emails
616. Terraform provider: manage compliance as infrastructure-as-code
617. GitHub/GitLab integration: compliance status checks on PRs
618. Connector development kit (CDK) with base classes, test harnesses, documentation
619. Normalizer development kit with schema validation, PII detection, test fixtures
620. Webhook connector for custom event ingestion
621. Drata and Vanta GRC platform findings for cross-platform visibility
622. Email security: Proofpoint, Mimecast, Barracuda, Abnormal Security
623. Endpoint management: Jamf, Kandji, Intune, Workspace One, Fleet, Automox
624. Network security: Palo Alto, Fortinet, F5, Cisco Umbrella, Zscaler, Netskope
625. DNS/DDoS: Cloudflare
626. Zero-trust: Tailscale, Twingate, Banyan, Zscaler
627. Secrets management: Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, 1Password, Bitwarden, CyberArk
628. Certificate management: DigiCert, Venafi, AWS ACM
629. Backup/recovery: AWS Backup, Rubrik, Veeam, Cohesity, Commvault, Druva
630. DLP: Nightfall, Varonis, Purview
631. API security: Salt Security, Noname, Wallarm, 42Crunch
632. Privacy platforms: OneTrust, TrustArc, Osano, Cookiebot, BigID

## Domain 16: Security & Access Control (25 capabilities)

633. RBAC with 4 roles: admin, auditor, owner, viewer
634. ABAC scope filtering: allowed_frameworks, allowed_sources, allowed_control_families, allowed_actions
635. API key management: SHA-256 hashed, configurable scopes, expiry, last_used tracking
636. MFA/TOTP support with mfa_secret, backup codes, verified_at
637. Account lockout via failed_login_count and locked_until
638. Token revocation via token_valid_after field
639. Refresh token support via refresh_token_hash
640. JWT authentication with configurable secret (32+ char minimum)
641. CORS configuration with empty default origins (never wildcard)
642. OPA policy gate enforcement with fail-closed default
643. Hash-chained audit trail: SHA-256 at every pipeline stage for tamper evidence
644. Immutable audit log preventing deletion/modification with cryptographic verification
645. Evidence integrity verification: re-compute SHA-256 for every RawEvent
646. Audit trail listing with hash chain verification: sequence, action, entity, actor, timestamp
647. Audit trail filtering by entity type, action type, actor, date range
648. User activity logging: login, search, export, approval, configuration changes
649. Audit sink external backends: Stdout (JSON-lines), S3 (Object Lock WORM), CloudWatch, SplunkHEC
650. S3AuditSink with Object Lock (GOVERNANCE/COMPLIANCE) and configurable retain_days
651. CloudWatchSink auto-creating log groups/streams with batch splitting
652. SplunkHECSink with exponential backoff retry
653. BatchShipper: accumulate AuditEntry objects, flush on batch size (500) or time interval (60s)
654. IP allowlisting for API and UI access
655. Session management: configurable timeout, concurrent limits, forced logout
656. Segregation of duties conflict detection
657. Data classification tagging with sensitivity labels

## Domain 17: AI & Machine Learning (25 capabilities)

658. AI-assisted control assessment as Tier 2 fallback with configurable confidence floor (0.7)
659. AI temperature forced to 0.0 for deterministic compliance results
660. AI provider configuration: Gemini, OpenAI, Anthropic
661. Prompt sanitization: <evidence> tags and control character stripping
662. Gemini API key in header (x-goog-api-key), never in URL
663. AI narrator: implementation narratives for SOC 2 and ISO 27001 reports
664. AI-powered executive briefing generation
665. AI risk narrative generation for framework risk analysis
666. AI audit readiness assessment with recommended actions
667. AI-enhanced remediation guidance per control/finding
668. Interactive AI reasoning sessions (conversational REPL with entity context)
669. AI-powered issue prioritization and triage
670. AI governance analysis of policy gaps
671. AI auto-suggest answers for vendor questionnaires with confidence scores
672. RAG-based semantic compliance queries over lake data
673. Semantic control mapping via embeddings for vector similarity matching
674. Anomaly detection using Isolation Forest with Z-score/IQR fallback
675. AI-powered natural language data lake queries
676. AI-powered horizon scanning for new regulations
677. AI-generated remediation steps based on finding type and environment
678. AI confidence distribution analysis with low-confidence flagging
679. AI model attribution tracking per ControlResult
680. AI task configuration: enable/disable specific AI tasks
681. AI DevTools for debugging AI assessments
682. Risk prediction and forecasting using historical posture data

## Domain 18: Platform & Infrastructure (45 capabilities)

683. 42 SQLAlchemy models covering full GRC lifecycle
684. 16 Alembic database migrations with reversibility verification
685. Domain service architecture: 7 modules implementing DomainService protocol
686. Domain registry for cross-domain service discovery
687. Domain event bus for cascade event propagation with correlation_id
688. Domain policy engine: operational policies with scope matching and specificity-based priority
689. Domain policy history tracking: every change with actor, action, old/new rules
690. Domain controls service: urgent items with severity-weighted priority scores
691. Domain evidence service: stale evidence detection and freshness metadata
692. Domain issues service: lifecycle integration with domain event propagation
693. QueryFilters: cross-domain queries filtered by frameworks, systems, owner, severity, since, limit
694. UrgentItem data structure with domain, type, ID, summary, severity, priority, action hint, SLA deadline
695. 153 FastAPI routes across 9 domain routers with ABAC enforcement
696. 374 CLI commands across 29 domain modules
697. TUI (terminal user interface) for keyboard-driven navigation
698. CLI --ai/--ask flags for AI-augmented command output
699. CLI briefing command for executive-level summaries
700. CLI control-hub for unified cross-domain control view
701. 12 Terraform IaC modules for AWS, Azure, GCP
702. 670 OPA/Rego policy files across 8 frameworks with tests and Regal linting
703. OSCAL catalog/profile JSON for 11 frameworks (17 files)
704. Docker demo workflow: migrations, seed, API server
705. Demo seed: 81 connectors, 358 raw events, ~5,008 findings, 373K+ mappings
706. GitHub Actions CI: ruff lint, pytest (509 tests), Docker build
707. GitHub Actions compliance gate: OPA, Terraform, OSCAL, Framework YAML validation
708. QA gate script: 20+ checks covering all aspects
709. Quick QA mode for fast development iteration
710. Pre-commit hook support
711. Multi-tenancy with tenant-level data isolation and independent configurations
712. White-label capability for MSSPs
713. Role hierarchy with inheritable permissions
714. Delegated administration for business unit leaders
715. Sandbox/staging environment for testing before production
716. Data import from legacy GRC tools: Archer, ServiceNow GRC, MetricStream, spreadsheets
717. Bulk data import via CSV, JSON, Excel
718. Connector development kit with base classes and test harnesses
719. Normalizer development kit with schema validation and test fixtures
720. Trust center with TrustAccessRequest model for customer-facing compliance sharing
721. Trust portal access request workflow (pending, approved, denied)
722. Trust document classification by tier (public, NDA, contract)
723. SDK and client libraries: Python, JavaScript/TypeScript, Go
724. Event-driven architecture with internal event bus for custom automation triggers
725. GraphQL or REST API with pagination, filtering, sorting, field selection, rate limiting
726. Compliance-as-code: version-controlled definitions in Git alongside infrastructure
727. Asset inventory integration mapping findings to IT assets, applications, business processes

## Domain 19: Incident & Business Continuity (20 capabilities)

728. Incident management: intake, classification, containment, eradication, recovery, lessons learned
729. Incident playbook library per type (data breach, ransomware, insider threat, DDoS)
730. Incident timeline reconstruction from log data, findings, manual entries
731. Incident impact assessment: affected records, notification requirements, financial exposure
732. Incident regulatory notification tracker per jurisdiction (GDPR 72h, state laws, SEC 4-day)
733. Post-incident review: root cause, corrective actions, control improvements
734. Incident-to-finding linkage connecting incidents to underlying control gaps
735. BCP management with creation, maintenance, testing, version control
736. Business impact analysis: RTO and RPO per business process
737. DR plan management with procedures, contacts, testing documentation
738. BCP/DR test scheduling and result tracking with pass/fail evaluation
739. Crisis communication templates for different scenarios
740. BCP/DR exercise management: tabletop, functional, full-scale with outcome capture
741. DR test results listing filtered by system and format
742. DR posture tracking via control-level compliance for CP-family controls
743. Incident response readiness assessment via IR scenario family
744. Change management risk tracking via CM scenario family
745. Operational risk event tracking across cloud, EDR, SIEM, scanner, IAM connectors
746. Cross-system dependency graph showing consumer/provider relationships
747. Provider system posture monitoring for inherited controls

## Domain 20: Search, UX & Accessibility (15 capabilities)

748. Full-text search across findings, controls, policies, risks, vendors, evidence, audit trail
749. Natural language query translation to structured queries
750. Saved filters with one-click recall and team sharing
751. Smart suggestions: auto-complete based on search history and context
752. Recent items and favorites bar
753. Faceted search with dynamic filter counts
754. Global command palette for rapid navigation
755. Fuzzy matching tolerating typos and abbreviations
756. Responsive web design for tablet and mobile
757. Mobile-optimized approval workflows
758. Offline evidence collection with later sync
759. Screen reader accessibility (WCAG 2.1 AA)
760. Full keyboard navigation
761. Dark mode, high-contrast mode, configurable font size/density
762. Session persistence preventing work loss on refresh

---

## Summary

| Domain | Capabilities |
|--------|-------------|
| 1. Compliance Posture Views | 82 |
| 2. Risk Quantification & Management | 65 |
| 3. POA&M Management | 25 |
| 4. Issue Management | 30 |
| 5. Vendor Risk Management | 35 |
| 6. Audit Management | 45 |
| 7. Framework Operations | 40 |
| 8. Security Posture & Vulnerability Mgmt | 55 |
| 9. Identity & Access Management | 25 |
| 10. Privacy & Data Governance | 30 |
| 11. Reporting & Export | 45 |
| 12. Automation & Pipeline | 50 |
| 13. Data Lake & Analytics | 40 |
| 14. Collaboration & Workflow | 30 |
| 15. Connectors & Integration | 35 |
| 16. Security & Access Control | 25 |
| 17. AI & Machine Learning | 25 |
| 18. Platform & Infrastructure | 45 |
| 19. Incident & Business Continuity | 20 |
| 20. Search, UX & Accessibility | 15 |
| **Total** | **762** |

Note: 1,417 raw capabilities were generated by 5 specialized agents, then deduplicated
and consolidated into 762 unique capabilities across 20 domains. Many raw items were
duplicates across agents or were sub-items of broader capabilities listed here.
