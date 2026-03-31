# Warlock CLI Reference

> **Note:** The canonical CLI reference is [`proddocs/api/cli-reference.md`](proddocs/api/cli-reference.md).
> This file is a quick-reference snapshot and may be stale. Regenerate with `warlock --help`.

**539 commands** across **101 top-level groups** covering the full GRC lifecycle.

Includes interactive workflows: investigate, triage, daily, morning, weekly,
monthly-review, audit-prep, incident-response, privacy-ops, vendor-review,
risk-review, audit-workflow, change-review, training-drive, exception-review,
conmon-monthly, evidence-sprint, onboard-system, system-review.

Generated from `warlock --help` on 2026-03-22.

> **TUI mode:** Running `warlock` without arguments in a terminal launches the
> interactive TUI dashboard (Textual). Use `warlock --no-tui` to force
> traditional CLI output, or set `WARLOCK_NO_TUI=1`. Non-TTY environments
> (pipes, CI) auto-detect and use CLI mode.

---

### warlock access-review

- `warlock access-review certify` — Record a certification decision for a user in a campaign.
- `warlock access-review create` — Create a new access review campaign.
- `warlock access-review list` — List access review campaigns.
- `warlock access-review overdue` — List all campaigns past their deadline.
- `warlock access-review report` — Generate a report for an access review campaign.
- `warlock access-review revoke` — Revoke a user's access in a campaign.
- `warlock access-review show` — Show campaign progress and certification details.
### warlock ai

- `warlock ai configure` — Configure the AI provider -- discover models and validate connectivity.
- `warlock ai models` — List available models for the configured provider.
- `warlock ai status` — Show AI service status -- provider, model, availability.
- `warlock ai test` — Send a test prompt to verify the AI provider is working.
### warlock ai-ops

- `warlock ai-ops analyze-vendor` — AI vendor risk analysis.
- `warlock ai-ops ask` — Open-ended AI Q&A about your GRC data.
- `warlock ai-ops audit-readiness` — AI assessment of audit readiness for a framework.
- `warlock ai-ops batch-classify` — Batch AI classification of findings by observation type and severity.
- `warlock ai-ops brief` — Generate an AI-powered compliance briefing.
- `warlock ai-ops classify-finding` — Auto-classify a finding by observation type and severity.
- `warlock ai-ops detect-drift` — Detect compliance drift patterns over a time window.
- `warlock ai-ops draft-exception` — Auto-draft a policy exception request with justification.
- `warlock ai-ops draft-poam` — Auto-draft a POA&M entry from a finding.
- `warlock ai-ops explain-control` — Explain a control's purpose, current status, and what evidence is needed.
- `warlock ai-ops explain-finding` — Explain what a finding means, why it matters, and how to fix it.
- `warlock ai-ops forecast` — Forecast compliance trajectory over a time horizon.
- `warlock ai-ops predict-risk` — Predict which controls are likely to fail based on historical trends.
- `warlock ai-ops prioritize` — AI-prioritized list of what to fix first.
- `warlock ai-ops review-evidence` — AI review of evidence sufficiency for a control.
- `warlock ai-ops root-cause` — AI root cause analysis from a finding and its control mappings.
- `warlock ai-ops suggest-remediation` — AI-suggested remediation steps for a finding.
- `warlock ai-ops summarize-posture` — Natural language compliance posture summary.
- `warlock architecture` — Render a live architecture diagram from the seeded database.
- `warlock ask` — Ask a compliance question (queries the data lake).
### warlock assertions

- `warlock assertions bindings` — List all control-to-assertion bindings.
- `warlock assertions bindings-for` — List all controls bound to a specific assertion.
- `warlock assertions coverage` — Show which controls have assertion coverage vs.
- `warlock assertions explain` — Explain an assertion: docstring, bindings, remediation, and recent results.
- `warlock assertions failures` — List recent assertion failures with failure reasons.
- `warlock assertions history` — Show recent DB results for a specific assertion.
- `warlock assertions list` — List all registered assertion functions.
- `warlock assertions run` — Run a single assertion with provided data dicts.
- `warlock assertions run-all` — Run all assertions against a shared detail dict.
- `warlock assertions show` — Show details for a specific assertion.
- `warlock assertions stats` — Show aggregate assertion pass/fail statistics from DB results.
- `warlock assertions test` — Smoke-test an assertion with safe default inputs.
### warlock attestations

- `warlock attestations create` — Create a new attestation in draft status.
- `warlock attestations expiring` — Show approved attestations expiring within N days (based on approved_at + 365 days).
- `warlock attestations history` — Show the audit trail for an attestation.
- `warlock attestations list` — List attestations, optionally filtered by status or framework.
- `warlock attestations overdue` — Show attestations that are past their prepared_at due date and not yet approved.
- `warlock attestations report` — Generate an attestation summary report by framework.
- `warlock attestations show` — Show full details of an attestation.
- `warlock attestations sign` — Sign (approve) an attestation.
### warlock audit

- `warlock audit corrective-actions` — List corrective action comments for an engagement.
### warlock audit engagement

- `warlock audit engagement create` — Create a new audit engagement.
- `warlock audit engagement list` — List audit engagements.
- `warlock audit engagement package` — Generate evidence binder package for an engagement.
- `warlock audit engagement show` — Show details of an audit engagement.
- `warlock audit engagement status` — Show progress summary for an engagement (control coverage, open items).
- `warlock audit findings-import` — Import findings from a CSV file into an engagement.
- `warlock audit-prep` — Interactive audit preparation checklist for FRAMEWORK.
### warlock audit-trail

- `warlock audit-trail export` — Export audit trail entries to JSON or CSV.
- `warlock audit-trail integrity-report` — Full hash chain integrity report.
- `warlock audit-trail list` — List recent audit trail entries.
- `warlock audit-trail retention-status` — Show retention policy status for audit trail entries.
- `warlock audit-trail search` — Search audit entries by text.
- `warlock audit-trail show` — Show full details for a single audit entry (by ID or sequence number).
- `warlock audit-trail stats` — Aggregate statistics for the audit trail.
- `warlock audit-trail tamper-detect` — Scan hash chain for any tamper evidence (breaks or mismatches).
- `warlock audit-trail timeline` — Show timeline of audit events for a specific entity.
- `warlock audit-trail user-activity` — Show activity summary per actor.
- `warlock audit-trail verify` — Verify hash chain integrity for a sequence range.
### warlock audit-workflow

- `warlock audit-workflow evidence-sprint` — Guided evidence collection sprint: triage controls and batch-create evidence requests.
- `warlock audit-workflow prepare` — Guided audit preparation: posture, evidence, POA&Ms, attestations, readiness score.
- `warlock audit-workflow respond` — Respond to auditor evidence requests for an engagement.
- `warlock audit-workflow simulate` — Project audit posture at a future date based on POA&M milestones and evidence expiry.
### warlock automation

- `warlock automation auto-issue` — Auto-create issues from findings that have no linked issue.
- `warlock automation auto-poam` — Auto-create POA&Ms from failed controls that have no existing POA&M.
- `warlock automation cleanup` — Archive old resolved issues, closed POA&Ms, and stale findings.
- `warlock automation collect-and-assess` — Targeted pipeline run: collect from specific sources and assess specific frameworks.
- `warlock automation refresh-evidence` — Re-collect evidence for controls with stale assessments.
### warlock automation rules

- `warlock automation rules create` — Create an automation rule.
- `warlock automation rules delete` — Mark an automation rule as deleted.
- `warlock automation rules list` — List all automation rules.
- `warlock automation rules test` — Test an automation rule against current data.
- `warlock automation run-all` — Run the full pipeline: collect -> normalize -> map -> assess -> report.
### warlock automation schedules

- `warlock automation schedules list` — Show all configured automation schedules.
- `warlock automation schedules set` — Create or update an automation schedule.
### warlock bcp

- `warlock bcp bia` — Business impact analysis for systems.
### warlock bcp dr-test

- `warlock bcp dr-test execute` — Record a DR test result for a system.
- `warlock bcp dr-test report` — Generate a DR test compliance report across all systems.
- `warlock bcp dr-test results` — List recorded DR test results.
- `warlock bcp dr-test schedule` — View DR test schedule by system (derived from active audit engagements).
- `warlock bcp systems` — List systems with their security impact / criticality tier.
- `warlock briefing` — Daily briefing — what needs attention across all domains.
### warlock bulk

- `warlock bulk acknowledge` — Bulk acknowledge findings for a framework / control family.
- `warlock bulk assign` — Bulk assign issues to a user.
- `warlock bulk close` — Bulk close (or verify/risk-accept) issues matching filters.
- `warlock bulk deduplicate` — Bulk deduplicate findings by sha256 hash, keeping the earliest ingested record.
- `warlock bulk escalate` — Bulk escalate high/critical issues to a specific user.
- `warlock bulk export` — Bulk export findings as JSON or CSV.
- `warlock bulk link-findings-to-issues` — Auto-create issues from unlinked critical/high findings.
- `warlock bulk reprocess` — Re-normalize raw events from a connector source.
- `warlock bulk stats` — Show counts of what each bulk operation would affect.
- `warlock bulk suppress` — Bulk suppress findings from a connector source.
- `warlock bulk tag` — Bulk tag findings from a source.
- `warlock bulk unsuppress` — Bulk unsuppress findings from a connector source.
- `warlock cadence` — Check monitoring cadence -- are controls being assessed on schedule?
### warlock calendar

- `warlock calendar add` — Add a compliance calendar item.
- `warlock calendar export` — Export the compliance calendar in ICS or CSV format.
- `warlock calendar list` — List compliance calendar items.
- `warlock calendar next` — Show everything due within the next N days across all GRC domains.
- `warlock calendar overdue` — Show all overdue items across every GRC domain.
- `warlock change-review` — Interactive Change Advisory Board (CAB) session.
- `warlock change-submit` — Guided change request submission workflow.
### warlock changes

- `warlock changes approve` — Approve a change request.
- `warlock changes create` — Create a new change request.
- `warlock changes emergency` — Escalate a change request to emergency status (bypasses normal approval).
- `warlock changes implement` — Mark a change request as implemented.
- `warlock changes list` — List change requests.
- `warlock changes reject` — Reject a change request.
- `warlock changes report` — Generate a change management summary report.
- `warlock changes show` — Show full details for a change request.
- `warlock collect` — Run the full pipeline: collect -> normalize -> map -> assess.
- `warlock compensating-controls` — List compensating controls.
### warlock comply

- `warlock comply audit-prep` — Pre-flight checklist for an upcoming audit: evidence freshness, coverage, POA&Ms, attestations.
- `warlock comply auto-map` — Auto-map unmapped findings to controls based on event_type matching.
- `warlock comply benchmark` — Compare compliance posture across all active frameworks.
- `warlock comply continuous-compliance` — Show current continuous compliance percentage by framework.
- `warlock comply control-effectiveness` — Analyze control pass/fail rates grouped by framework.
- `warlock comply debt` — Show compliance debt: overdue POA&Ms, expired attestations, stale evidence.
- `warlock comply executive-brief` — Generate a one-page executive compliance brief.
- `warlock comply gap-close` — Suggest remediation actions for failed controls.
- `warlock comply maturity-model` — Assess GRC program maturity on a 1-5 scale.
- `warlock comply pre-audit` — Generate a pre-audit report for a framework.
- `warlock comply quick-wins` — Identify lowest-effort, highest-impact compliance improvements.
- `warlock comply readiness-score` — Compute a 0-100 readiness score with breakdown for a framework.
- `warlock comply regression-check` — Identify controls that have regressed (pass -> fail) recently.
- `warlock comply remediation-plan` — Generate a prioritized remediation plan for non-compliant controls.
- `warlock comply schedule-audit` — Recommend an audit timeline based on current compliance posture.
### warlock conmon

- `warlock conmon checklist` — Display the monthly ConMon checklist with current completion status.
- `warlock conmon deviation` — Create a ConMon deviation record for a control.
- `warlock conmon monthly-report` — Generate a ConMon monthly report for submission.
- `warlock conmon significant-change` — Record a significant change for ConMon review.
- `warlock conmon status` — Show current continuous monitoring status across frameworks.
- `warlock conmon-monthly` — Full monthly Continuous Monitoring (ConMon) workflow.
### warlock connectors

- `warlock connectors collect` — Run a single connector's collect() method.
- `warlock connectors collect-all` — Run collect() on all enabled active connectors.
- `warlock connectors compare` — Compare event counts and source types for two connectors.
- `warlock connectors credentials` — Show which env vars a connector requires (never shows values).
- `warlock connectors credentials-check` — Check credential env vars for all active connectors.
- `warlock connectors disable` — Disable a connector (sets config.enabled = False).
- `warlock connectors enable` — Enable a connector (sets config.enabled = True).
- `warlock connectors errors` — Show connectors with errors from recent runs.
- `warlock connectors event-types` — List all event_types across all connectors.
- `warlock connectors export` — Export connector run history to JSON.
- `warlock connectors health` — Show an overall health summary of all connectors.
- `warlock connectors history` — Show run history for a specific connector.
- `warlock connectors import` — Import connector configurations from a JSON file (metadata only).
- `warlock connectors list` — List all registered connectors.
- `warlock connectors schedule` — Show poll intervals for active connectors.
- `warlock connectors schema` — Show the raw event schema (event_types) produced by a connector.
- `warlock connectors show` — Show details for a specific connector.
- `warlock connectors stats` — Aggregate connector statistics by source_type.
- `warlock connectors status` — Show recent run status for all connectors.
- `warlock connectors test` — Run health_check() on a connector.
- `warlock connectors test-all` — Run health_check() on all active connectors.
- `warlock connectors validate` — Validate connector configuration (check required fields).
- `warlock connectors validate-all` — Validate all active connector configurations.
- `warlock control` — Show control detail: status, resources, and remediation guidance.
- `warlock control-hub` — Cross-domain view of a control: status, evidence, issues, risk, owner.
### warlock control-tests

- `warlock control-tests due` — List controls due for testing within the next N days.
- `warlock control-tests execute` — Record a manual control test result.
- `warlock control-tests gaps` — List controls that have never been tested or are past-due.
- `warlock control-tests history` — Show test history for a control.
- `warlock control-tests report` — Generate a control testing report by framework.
- `warlock control-tests schedule` — View control test schedule grouped by control family.
- `warlock control-tests schedule-set` — Set the testing cadence for a specific control.
### warlock correlate

- `warlock correlate blast-radius` — How many controls, frameworks, and systems are affected by a finding.
- `warlock correlate common-findings` — Findings that map to multiple frameworks.
- `warlock correlate control-to-evidence` — Show evidence (ControlResult evidence_ids) for a control.
- `warlock correlate control-to-findings` — Show all findings mapped to a control.
- `warlock correlate coverage-matrix` — Matrix of connectors x controls showing coverage for a framework.
- `warlock correlate dependency-map` — Show cross-system dependency graph.
- `warlock correlate finding-to-controls` — Show all controls mapped to a finding via ControlMapping.
- `warlock correlate finding-to-incident` — Show incidents (issues) linked to a finding.
- `warlock correlate gap-analysis` — Comprehensive gap analysis: missing connectors, unmapped controls, stale evidence, failed assertions.
- `warlock correlate impact-analysis` — Which findings, frameworks, and issues are affected if this control fails.
- `warlock correlate incident-to-findings` — Show all findings linked to an incident (issue).
- `warlock correlate orphan-controls` — Controls with no findings or evidence (from ControlResult).
- `warlock correlate orphan-findings` — Findings with no control mapping.
- `warlock correlate timeline-correlation` — Correlated timeline of findings, incidents, and change events.
- `warlock correlate trace` — Full trace: finding -> controls -> results -> evidence -> audit trail.
- `warlock coverage` — Show compliance coverage summary.
- `warlock daily` — Daily GRC practitioner morning summary and workflow launcher.
### warlock dashboard

### warlock dashboard alerts

- `warlock dashboard alerts acknowledge` — Acknowledge an active alert by ID.
- `warlock dashboard alerts configure` — Configure alert notifications for a KRI.
- `warlock dashboard alerts history` — Show alert history for the past N days.
- `warlock dashboard alerts list` — List alerts filtered by status.
- `warlock dashboard executive` — Board-level summary: overall score, top risks, trending items, and open actions.
### warlock dashboard kri

- `warlock dashboard kri evaluate` — Evaluate all KRIs against thresholds and show red/amber/green status.
- `warlock dashboard kri list` — List all Key Risk Indicators with current values and threshold status.
- `warlock dashboard kri set-threshold` — Update warning and critical thresholds for a KRI.
- `warlock dashboard kri show` — Show KRI detail with current value and thresholds.
- `warlock dashboard kri trend` — Show KRI trend summary as sparklines (terminal-based mini charts).
- `warlock dashboard live` — Real-time compliance dashboard (Rich Live display).
- `warlock dashboard operations` — Ops-focused view: connector health, pipeline status, data freshness, and errors.
- `warlock dashboard posture` — Current compliance posture summary across all or selected frameworks.
- `warlock dashboard program` — GRC program health: training, attestation coverage, evidence freshness, POA&M aging.
- `warlock dashboard security` — Security-focused view: vulnerability counts, MTTR, and active incidents.
- `warlock data-silos` — List discovered data silos.
- `warlock data-silos-discover` — Auto-discover data silos from findings.
- `warlock dependencies` — Show cross-system dependency graph.
- `warlock drift` — Show compliance drift events with correlated changes.
- `warlock effectiveness` — Show control effectiveness scores over time.
### warlock evidence

- `warlock evidence attach` — Attach a file as evidence for a control result.
- `warlock evidence chain` — Show the hash chain provenance for an evidence record.
- `warlock evidence export` — Export evidence records to a compressed archive.
- `warlock evidence freshness` — Show evidence freshness report — which controls have stale or missing assessments.
- `warlock evidence gaps` — Show controls missing evidence (no evidence_ids attached).
- `warlock evidence list` — List control results with evidence metadata.
- `warlock evidence package` — Bundle all evidence for a framework into an auditor package.
### warlock evidence requests

- `warlock evidence requests assign` — Assign an evidence request to a user.
- `warlock evidence requests create` — Create an auditor evidence request.
- `warlock evidence requests fulfill` — Mark an evidence request as fulfilled.
- `warlock evidence requests import` — Bulk import evidence requests from a CSV file.
- `warlock evidence requests list` — List auditor evidence requests.
- `warlock evidence requests overdue` — Show overdue evidence requests with SLA countdown.
- `warlock evidence show` — Show full detail for an evidence record (control result).
- `warlock evidence stats` — Show evidence statistics by framework and status.
- `warlock evidence timeline` — Show assessment history for a control over time.
- `warlock evidence verify` — Verify the hash chain integrity for an evidence record.
- `warlock evidence-collection` — Interactive evidence collection: fulfill pending evidence requests.
- `warlock evidence-sprint` — Guided evidence collection sprint for a framework.
- `warlock exception-review` — Review policy exceptions (risk acceptances) expiring within N days.
### warlock exceptions

- `warlock exceptions create` — Create a new policy exception.
- `warlock exceptions expiring` — List exceptions expiring within N days.
- `warlock exceptions list` — List policy exceptions.
- `warlock exceptions renew` — Renew a policy exception with a new expiry date.
- `warlock exceptions report` — Generate a policy exceptions summary report.
- `warlock exceptions show` — Show full details for a policy exception.
### warlock findings

- `warlock findings aging` — Age analysis of findings (KRI metric).
- `warlock findings annotate` — Add an annotation note to a finding's detail dict.
- `warlock findings by-connector` — Group finding counts by connector (source + provider).
- `warlock findings by-control` — Group finding counts by mapped control.
- `warlock findings deduplicate` — Identify findings with duplicate sha256 hashes.
- `warlock findings export` — Export findings to JSON or CSV.
- `warlock findings list` — List normalized findings.
- `warlock findings search` — Full-text search findings by title.
- `warlock findings show` — Show full detail for a finding.
- `warlock findings sla` — Show findings by SLA compliance window (30/60/90-day).
- `warlock findings stats` — Aggregate finding statistics by severity, source type, and observation type.
- `warlock findings suppress` — Suppress a finding (sets pii_detected flag as suppression marker).
- `warlock findings timeline` — Show daily finding counts over a time window.
- `warlock findings trending` — Show finding open/close rate trends by source over a time window.
- `warlock findings unsuppress` — Remove suppression from a finding.
- `warlock framework-diff` — Compare two framework versions and show control changes.
### warlock frameworks

### warlock frameworks baselines

- `warlock frameworks baselines apply` — Apply a baseline: show controls that fall within the baseline scope.
- `warlock frameworks baselines list` — List available baselines.
- `warlock frameworks baselines show` — Show controls in a baseline (e.g.
- `warlock frameworks calendar` — Show monitoring frequency calendar for a framework's controls.
- `warlock frameworks compare` — Compare two frameworks: shared families, control overlap, unique controls.
- `warlock frameworks connectors` — List connectors that feed data relevant to this framework.
- `warlock frameworks controls` — List controls for a framework.
- `warlock frameworks coverage` — Show control coverage: which controls have findings in the DB.
- `warlock frameworks crosswalk` — Show crosswalk mappings from a source framework.
- `warlock frameworks event-types` — List all event types referenced by a framework's controls.
- `warlock frameworks export` — Export a framework definition to JSON or YAML.
- `warlock frameworks gaps` — Show controls with no compliant findings (gaps).
- `warlock frameworks heatmap` — Compliance heatmap by control family.
- `warlock frameworks inheritance` — Show control inheritance report from inherited_controls.yaml.
### warlock frameworks inherited

- `warlock frameworks inherited list` — List all inherited control sets.
- `warlock frameworks inherited show` — Show controls for a specific provider and inheritance type.
- `warlock frameworks list` — List all available compliance frameworks.
- `warlock frameworks show` — Show details for a specific framework.
- `warlock frameworks stats` — Aggregate statistics across all frameworks.
### warlock incident-response

- `warlock incident-response drill` — Tabletop exercise — simulated incident response drill.
- `warlock incident-response manage` — Incident lifecycle management loop.
- `warlock incident-response new` — Guided incident creation workflow.
- `warlock incident-response postmortem` — Guided post-mortem documentation workflow.
### warlock incidents

- `warlock incidents add-event` — Append a manual event to an incident's audit trail.
- `warlock incidents close` — Close an incident with a resolution and optional lessons learned.
- `warlock incidents create` — Create a new incident.
- `warlock incidents link` — Link a finding to an incident.
- `warlock incidents list` — List incidents (open/investigating by default).
- `warlock incidents metrics` — Show MTTR, frequency by category, and severity distribution.
- `warlock incidents report` — Generate a post-mortem report for an incident.
- `warlock incidents responders` — Manage responders (assigned_to) for an incident.
- `warlock incidents show` — Show full detail for an incident.
- `warlock incidents timeline` — Show audit trail events for an incident.
- `warlock incidents update` — Update the status of an incident.
- `warlock ingest` — Ingest a JSON file through the webhook receiver and pipeline.
- `warlock inheritance` — Show control inheritance map for a system.
- `warlock init` — Initialize the database.
### warlock integrations

- `warlock integrations configure` — Configure an external integration.
- `warlock integrations list` — List configured integrations and their status.
### warlock integrations notifications

- `warlock integrations notifications configure` — Configure a notification channel.
- `warlock integrations notifications list` — List configured notification channels.
- `warlock integrations notifications rules-create` — Create a notification routing rule.
- `warlock integrations notifications rules-delete` — Delete a notification routing rule (recorded as deletion event).
- `warlock integrations notifications rules-list` — List notification routing rules (from audit log).
- `warlock integrations notifications test` — Send a test notification to verify a channel is working.
- `warlock integrations status` — Show health status of all configured integrations.
- `warlock integrations test` — Send a test event to verify an integration is working.
### warlock investigate

- `warlock investigate control` — Deep investigation of a specific control by CONTROL_ID (e.g.
- `warlock investigate finding` — Deep investigation of a specific finding by FINDING_ID (or prefix).
- `warlock investigate framework` — Interactive compliance investigation for a specific FRAMEWORK_NAME.
- `warlock investigate source` — Interactive investigation of all non-compliant findings for SOURCE_NAME.
- `warlock issues` — List and manage compliance issues.
- `warlock issues-auto-create` — Auto-create issues from non-compliant control results.
### warlock lake

- `warlock lake aggregate` — Refresh materialized aggregation tables.
### warlock lake analytics

- `warlock lake analytics heatmap` — Show control family compliance heatmap.
- `warlock lake analytics trends` — Show compliance posture trends.
- `warlock lake assess` — Run batch aggregate control assessment from lake data.
- `warlock lake backfill` — Backfill historical OLTP data to the lake.
- `warlock lake compact` — Compact small Parquet files into larger ones.
### warlock lake evidence

- `warlock lake evidence freshness` — Show evidence freshness status.
- `warlock lake evidence list` — List evidence artifacts from the lake.
### warlock lake health

- `warlock lake health coverage` — Show data coverage metrics.
- `warlock lake health freshness` — Show data freshness per connector.
- `warlock lake health runs` — Show recent pipeline runs.
### warlock lake incidents

- `warlock lake incidents events` — List security events.
- `warlock lake incidents list` — List incidents from the lake.
- `warlock lake init` — Create lake directory structure (raw/enrichment/curated zones).
- `warlock lake maintenance` — Run all lake maintenance jobs (compact, expire, cleanup).
### warlock lake privacy

- `warlock lake privacy dsars` — List DSAR requests.
- `warlock lake privacy processing` — List processing activities (GDPR Art.
- `warlock lake privacy transfers` — List cross-border data transfers.
- `warlock lake query` — Query the lake with a natural language question.
- `warlock lake reconcile` — Compare OLTP row counts with lake row counts.
- `warlock lake register` — Register lake tables with the Iceberg catalog.
- `warlock lake status` — Show lake status (zones, file counts, total size).
### warlock lake supply-chain

- `warlock lake supply-chain concentration` — Show concentration risk analysis.
- `warlock lake supply-chain sbom` — List SBOM components.
- `warlock lake supply-chain suppliers` — List supplier assessments.
- `warlock lake thin-oltp` — Remove historical records from OLTP (keep latest per control only).
### warlock lake-analytics

### warlock lake-analytics anomaly

- `warlock lake-analytics anomaly detect` — Detect anomalies in finding volume and severity patterns.
- `warlock lake-analytics anomaly investigate` — Drill into findings on a specific anomalous date (YYYY-MM-DD).
- `warlock lake-analytics anomaly list` — List detected anomalies in the data lake (days with abnormal finding counts).
- `warlock lake-analytics compact` — Compact small Parquet files in the lake to reduce file-count overhead.
- `warlock lake-analytics compare-runs` — Delta analysis between two pipeline connector runs.
- `warlock lake-analytics export-parquet` — Export lake data to Parquet files.
- `warlock lake-analytics freshness` — Show data freshness per source, flagging stale sources.
- `warlock lake-analytics lineage` — Trace a finding back through raw events to the originating connector.
- `warlock lake-analytics partitions` — Show partition layout and sizes in the lake directory.
- `warlock lake-analytics purge` — Purge old data from the lake per the retention policy.
- `warlock lake-analytics quality` — Report data quality metrics: nulls, duplicates, and schema violations.
- `warlock lake-analytics query` — Execute a SQL query directly against the data lake (DuckDB).
- `warlock lake-analytics retention` — Show the data retention policy and what data is eligible for purge.
- `warlock lake-analytics sources` — List all data sources in the lake with row counts and last-updated timestamps.
- `warlock lake-analytics summary` — Overview of lake contents: row counts, date ranges, sources, freshness.
### warlock lake-analytics trends

- `warlock lake-analytics trends connectors` — Show connector data volume trends over time.
- `warlock lake-analytics trends controls` — Show control pass/fail trends over time.
- `warlock lake-analytics trends findings` — Show finding volume trends over time.
- `warlock lake-analytics trends risk` — Show risk score trends (severity distribution over time).
- `warlock lake-analytics volume` — Show data volume trends grouped by a chosen dimension.
- `warlock monthly-review` — Monthly GRC review: KRI evaluation, ConMon, vendors, training, attestations.
- `warlock morning` — Morning operations review: overnight summary and attention items.
- `warlock onboard-system` — Guided system authorization (ATO) onboarding workflow.
### warlock oscal

- `warlock oscal assessment-results` — Export OSCAL assessment results for a framework.
### warlock oscal catalogs

- `warlock oscal catalogs list` — List available OSCAL catalog packages.
- `warlock oscal catalogs show` — Show controls from an OSCAL catalog.
- `warlock oscal poam` — Export an OSCAL POA&M document.
### warlock oscal profiles

- `warlock oscal profiles list` — List available OSCAL profile files.
- `warlock oscal profiles show` — Show an OSCAL profile for a framework.
- `warlock oscal ssp` — Export an OSCAL System Security Plan (SSP) for a framework.
- `warlock oscal validate` — Validate an OSCAL JSON file for structural correctness.
- `warlock personnel` — List personnel records with HR/IdP/training cross-reference.
- `warlock personnel-sync` — Sync personnel records from HR, IdP, and training findings.
### warlock pipeline

- `warlock pipeline compare` — Compare two pipeline runs side-by-side.
- `warlock pipeline errors` — Show error details from recent pipeline runs.
- `warlock pipeline hash-verify` — Verify SHA-256 integrity of all raw events in a connector run.
- `warlock pipeline history` — Show full pipeline run history with filters.
- `warlock pipeline replay` — Replay normalisation and assessment for an existing raw event collection run.
- `warlock pipeline run` — Trigger a new pipeline run (collect -> normalize -> map -> assess).
### warlock pipeline schedule

- `warlock pipeline schedule set` — Set the scheduler interval (requires a running scheduler).
- `warlock pipeline schedule show` — Show current scheduler configuration.
- `warlock pipeline stats` — Show aggregate pipeline statistics across all runs.
- `warlock pipeline status` — Show the status of recent pipeline runs.
- `warlock pipeline verify-chain` — Verify the SHA-256 hash chain integrity of the audit trail.
### warlock poam

- `warlock poam deviation` — Record a deviation on a POA&M (false positive, vendor dependency, etc.).
- `warlock poam milestone-update` — Update a specific milestone on a POA&M.
- `warlock poam milestones` — Show all milestones for a POA&M.
- `warlock poams` — List Plans of Action & Milestones.
### warlock policies

- `warlock policies check` — Syntax-check all Rego files.
- `warlock policies coverage` — Show which controls have OPA policy coverage.
- `warlock policies diff` — Compare OPA policy coverage between two frameworks.
- `warlock policies evaluate` — Evaluate an OPA policy against a JSON input.
- `warlock policies export` — Export a policy Rego file to a destination.
### warlock policies lifecycle

- `warlock policies lifecycle acknowledge` — Record acknowledgment of a policy (extends review timestamp in history).
- `warlock policies lifecycle list` — List active Policy DB records.
- `warlock policies lifecycle review-due` — List policies that are expiring or due for review.
- `warlock policies list` — List all OPA policy files.
- `warlock policies search` — Search policy file content for a pattern.
- `warlock policies show` — Show the content of a policy file.
- `warlock policies stats` — Aggregate OPA policy statistics.
- `warlock policies test` — Run OPA tests for a specific framework.
- `warlock policies test-all` — Run all OPA tests across all policy directories.
- `warlock policies unused` — Show frameworks that have no OPA policy coverage.
### warlock policy

- `warlock policy history` — Show policy change history.
- `warlock policy list` — List active policies.
- `warlock policy set` — Push a policy to the system.
- `warlock policy show` — Show policies affecting a specific entity.
- `warlock policy-coverage` — Check policy documentation coverage for a framework.
- `warlock posture-history` — Show posture trends over time per control.
### warlock privacy

### warlock privacy breach

- `warlock privacy breach create` — Record a new personal data breach.
- `warlock privacy breach notify` — Record that the regulatory authority has been notified.
- `warlock privacy breach show` — Show details of a recorded breach.
- `warlock privacy breach status` — Show notification status for a breach.
- `warlock privacy data-map` — Show inventory of all data silos (data map).
### warlock privacy dsar

- `warlock privacy dsar create` — Create a new DSAR record.
- `warlock privacy dsar escalate` — Escalate a DSAR for manual review.
- `warlock privacy dsar fulfill` — Mark a DSAR as fulfilled.
- `warlock privacy dsar list` — List DSAR records.
- `warlock privacy dsar overdue` — List DSARs past their deadline with SLA countdown.
- `warlock privacy dsar show` — Show full details of a DSAR.
- `warlock privacy impact-assess` — Run a basic DPIA (Data Protection Impact Assessment) for a system.
- `warlock privacy ropa` — Generate a Record of Processing Activities (ROPA) from the data map.
### warlock privacy transfers

- `warlock privacy transfers list` — List recorded data transfers.
- `warlock privacy transfers validate` — Validate that all recorded transfers have an accepted mechanism.
### warlock privacy-ops

- `warlock privacy-ops breach-response` — Guided data breach notification workflow.
- `warlock privacy-ops data-map-review` — Interactive data map review workflow.
- `warlock privacy-ops dsar-intake` — Guided Data Subject Access Request intake and processing workflow.
- `warlock privacy-ops impact-assessment` — Guided Data Protection Impact Assessment (DPIA) for a system.
- `warlock questionnaires` — List vendor questionnaires.
- `warlock questionnaires-seed` — Seed default questionnaire templates (SIG Lite, DDQ).
- `warlock remediate` — Show remediation guidance and take action on issues/POA&Ms.
- `warlock remediate-guided` — Guided remediation workflow for a finding ID or control ID.
### warlock reports

- `warlock reports attestation-summary` — Summarise attestation status across all controls.
- `warlock reports audit-readiness` — Summarise audit readiness: evidence coverage, open issues, stale data.
- `warlock reports board` — Generate board-level GRC summary (high-level risk and posture metrics).
- `warlock reports compliance` — Detailed per-control compliance status for a framework.
- `warlock reports conmon` — Continuous monitoring status report (FedRAMP ConMon style).
- `warlock reports connector-health` — Show recent connector run health summary.
- `warlock reports executive` — Generate executive compliance posture summary.
- `warlock reports generate` — Generate a formatted report and optionally save to file.
- `warlock reports history` — Show recent report generation history from audit log.
- `warlock reports kpi` — Display Key Performance Indicators for the compliance program.
- `warlock reports kri` — Display Key Risk Indicators.
- `warlock reports risk` — Show top open risk items (issues + POA&Ms) by severity.
- `warlock reports schedule` — Schedule recurring report delivery (recorded to audit log).
- `warlock reports sla` — Show SLA compliance for issue resolution times.
### warlock reports templates

- `warlock reports templates list` — List available report templates.
- `warlock reports trend` — Show compliance posture trend over time (from posture snapshots).
- `warlock results` — Query control results from the last pipeline run.
### warlock retention

- `warlock retention purge` — Purge records past their retention period.
- `warlock retention report` — Show retention report: record ages, purgeable counts, legal holds.
### warlock risk

- `warlock risk analyze` — Run FAIR risk quantification for a framework.
- `warlock risk cache-stats` — Show Monte Carlo DB cache statistics.
- `warlock risk invalidate` — Delete cached Monte Carlo entries from the database.
- `warlock risk precompute` — Pre-warm the Monte Carlo cache for all active frameworks.
- `warlock risk-acceptances` — List risk acceptances.
### warlock risk-engine

- `warlock risk-engine aggregate` — Aggregate risk exposure across the portfolio by a chosen dimension.
### warlock risk-engine appetite

- `warlock risk-engine appetite check` — Compare current risk exposure against appetite thresholds.
- `warlock risk-engine appetite list` — Show risk appetite thresholds by category.
- `warlock risk-engine appetite set` — Set a risk appetite threshold for a category.
- `warlock risk-engine exposure` — Show total risk exposure by framework from live control results.
- `warlock risk-engine heatmap` — Display risk heatmap by likelihood x impact (5x5 grid).
- `warlock risk-engine quantify` — Estimate risk in dollar terms for a single finding.
- `warlock risk-engine quantify-bulk` — Batch FAIR risk quantification across findings portfolio.
### warlock risk-engine register

- `warlock risk-engine register add` — Add a new entry to the risk register.
- `warlock risk-engine register list` — List risk register entries.
- `warlock risk-engine register show` — Show details for a single risk register entry (RISK_ID prefix or full UUID).
- `warlock risk-engine register update` — Update an existing risk register entry (RISK_ID prefix or full UUID).
- `warlock risk-engine simulate` — Run Monte Carlo simulation across the full risk portfolio.
- `warlock risk-engine top-risks` — Show the highest quantified risks from the register.
### warlock risk-engine treatment

- `warlock risk-engine treatment add` — Add a treatment plan to a risk register entry (RISK_ID prefix or full UUID).
- `warlock risk-engine treatment list` — Show treatment plans for a given risk (RISK_ID prefix or full UUID).
- `warlock risk-engine treatment update` — Update the status of a treatment plan (prefix or full UUIDs).
- `warlock risk-engine trend` — Show risk trend over time (findings per day for the past N days).
### warlock risk-review

- `warlock risk-review acceptance` — Guided risk acceptance workflow for a finding.
- `warlock risk-review assess` — Guided risk assessment session: review top risks and new critical/high findings.
- `warlock risk-review board-report` — Generate a board-level risk report interactively.
- `warlock risk-review quarterly` — Quarterly risk review: reassess risk ratings, update heatmap, generate report.
### warlock scheduler

- `warlock scheduler start` — Start the pipeline scheduler.
- `warlock scheduler status` — Show scheduler status.
- `warlock simulate-audit` — Simulate what an auditor would see at a future date.
### warlock sod

- `warlock sod analyze` — Analyze user roles for Segregation of Duties conflicts.
- `warlock sod conflicts` — Show known SoD conflict rules and any current violations.
- `warlock sod matrix` — Display the role-permission matrix showing access rights per role.
- `warlock sources` — List all registered connector types and normalizer types.
- `warlock sufficiency` — Show evidence sufficiency scores per control.
- `warlock system-review` — Interactive system security review.
- `warlock systems` — List active system profiles.
- `warlock systems-create` — Create a new system profile.
### warlock terraform

- `warlock terraform compliance` — Show Terraform module compliance coverage by framework.
- `warlock terraform drift` — Check for configuration drift by running terraform plan -detailed-exitcode.
### warlock terraform modules

- `warlock terraform modules list` — List available Terraform modules.
- `warlock terraform modules show` — Show details for a specific Terraform module.
- `warlock terraform plan` — Run terraform plan for a specific module (dry-run, no apply).
- `warlock terraform validate` — Run terraform validate on all modules (or a specific module).
### warlock training

- `warlock training campaigns` — List training campaigns derived from personnel completion records.
- `warlock training overdue` — List personnel with overdue training.
- `warlock training report` — Generate a full training compliance report.
- `warlock training status` — Show training completion rates, optionally by department or role.
- `warlock training-drive` — Training campaign management: completion rates, overdue personnel, escalations.
- `warlock triage` — Interactive finding triage -- work through unreviewed findings by severity.
### warlock users

- `warlock users audit-log` — Show the audit trail for a user.
- `warlock users create` — Create a new platform user.
- `warlock users deactivate` — Deactivate a user account (non-destructive).
- `warlock users list` — List platform users.
- `warlock users permissions` — Show effective permissions for a user.
### warlock users roles

- `warlock users roles create` — Document a custom role (informational — persisted to audit log only).
- `warlock users roles list` — List available roles and their default permissions.
- `warlock users roles show` — Show users assigned to a specific role.
### warlock users scopes

- `warlock users scopes assign` — Add a scope restriction to a user.
- `warlock users scopes list` — List scope restrictions for a user.
- `warlock users sessions` — Show recent session activity for a user.
- `warlock users show` — Show details for a specific user.
- `warlock users sod-check` — Check for Segregation of Duties conflicts for a user.
- `warlock users update` — Update a user's name, role, or active state.
### warlock vendor-mgmt

- `warlock vendor-mgmt assess` — Record a risk assessment result for a vendor.
- `warlock vendor-mgmt concentration` — Analyse vendor concentration risk (tier distribution and high-risk count).
- `warlock vendor-mgmt contracts` — List vendors with contracts expiring soon.
- `warlock vendor-mgmt create` — Register a new vendor.
- `warlock vendor-mgmt export` — Export all vendor records to JSON.
- `warlock vendor-mgmt fourth-party` — List fourth-party (sub-processor) dependencies for a vendor.
- `warlock vendor-mgmt history` — Show assessment history for a vendor.
- `warlock vendor-mgmt incidents` — Show security incidents associated with vendors.
- `warlock vendor-mgmt list` — List all vendors.
- `warlock vendor-mgmt offboard` — Offboard a vendor (mark as inactive and record reason).
- `warlock vendor-mgmt questionnaire` — Manage vendor security questionnaires.
- `warlock vendor-mgmt reassess-due` — List vendors that are due for reassessment.
- `warlock vendor-mgmt risk-score` — Display the current risk score and scoring breakdown for a vendor.
- `warlock vendor-mgmt show` — Show detailed information for a vendor.
- `warlock vendor-mgmt sla` — View or update SLA terms for a vendor.
- `warlock vendor-mgmt soc2-review` — Record or display SOC 2 report review for a vendor.
### warlock vendor-review

- `warlock vendor-review assess` — Guided vendor risk assessment workflow.
- `warlock vendor-review offboard` — Guided vendor offboarding workflow.
- `warlock vendor-review onboard` — Guided vendor onboarding workflow.
- `warlock vendor-review reassess` — Batch vendor reassessment workflow.
- `warlock vendors` — Score and monitor vendor risk.
### warlock vulns

- `warlock vulns accept` — Accept (risk-accept) a vulnerability finding.
- `warlock vulns aging` — Show oldest open vulnerabilities exceeding a minimum age.
- `warlock vulns by-scanner` — Show vulnerability counts broken down by scanner/source.
- `warlock vulns dashboard` — Show vulnerability posture dashboard.
- `warlock vulns remediation-rate` — Show vulnerability remediation rate for the given period.
- `warlock vulns report` — Generate a vulnerability management report.
- `warlock vulns sla-breach` — List vulnerabilities that have breached their SLA thresholds.
- `warlock vulns trends` — Show vulnerability discovery trends over the last N days.
- `warlock weekly` — Weekly operations summary: week-over-week metrics, connector health, deadlines.
