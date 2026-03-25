# SOC 2 Type II Audit Walkthrough

This guide walks through a complete SOC 2 Type II audit preparation cycle using Warlock. Each section maps to a phase of the audit lifecycle, from initial posture assessment through OSCAL export for your auditor.

SOC 2 in Warlock covers 46 controls across 12 Trust Services Criteria families: CC1 through CC9 (Common Criteria), A1 (Availability), C1 (Confidentiality), PI1 (Processing Integrity), and P1 (Privacy).

## Prerequisites

Run the demo seed to populate your environment with SOC 2 control results, findings, issues, and POA&Ms.

```bash
make demo
```

After seeding completes, verify SOC 2 data exists:

```bash
warlock results -f soc2 --limit 5
```

You should see control results for SOC 2 controls (CC1.1, CC6.1, etc.) with statuses like `compliant`, `non_compliant`, or `partial`.

---

## Step 1: Posture Assessment

Start by understanding your current SOC 2 compliance posture. This answers the first question any audit team asks: "Where do we stand?"

### View SOC 2 posture score

```bash
warlock dashboard posture -f soc2
```

Displays the compliance rate for SOC 2: total controls, compliant count, not-assessed count, and an assessed compliance percentage. A score above 80% with zero open issues is the threshold for audit readiness.

### Benchmark against other frameworks

```bash
warlock comply benchmark -f soc2
```

Shows SOC 2 alongside every other active framework in a ranked comparison table with pass rates and visual bars. Useful for board reporting and for identifying whether SOC 2 is ahead of or behind your other compliance programs.

### Daily briefing scoped to SOC 2

```bash
warlock briefing -f soc2
```

A prioritized summary of what needs attention today: overdue POA&Ms, stale evidence, non-compliant controls, and recent drift events, all filtered to SOC 2.

---

## Step 2: Control Review

Drill into individual control families and their assessment results.

### Per-control compliance status

```bash
warlock reports compliance -f soc2 -n 100
```

Lists every SOC 2 control with its current status (compliant, non_compliant, partial, not_assessed), severity, assessor type, and assessment date. Use `-n 100` to see all 46 controls.

### Cross-domain control view

```bash
warlock control-hub CC6.1 -f soc2
```

Deep dive into a single control. Shows the control definition, mapped findings, assessment history, related controls in other frameworks (via crosswalks), and evidence chain. CC6.1 (Logical and Physical Access Controls) is typically the most evidence-intensive SOC 2 control.

### Findings mapped to SOC 2

```bash
warlock findings list -f soc2
```

Lists normalized findings that map to SOC 2 controls. Each finding traces back to a specific connector and raw event. Filter further by severity:

```bash
warlock findings list -f soc2 -s critical
```

---

## Step 3: Evidence Collection

SOC 2 Type II requires evidence that controls operated effectively over a period (typically 6-12 months). Warlock tracks evidence freshness, sufficiency, and gaps automatically.

### List evidence for SOC 2 controls

```bash
warlock evidence list -f soc2
```

Shows control results with evidence metadata: when evidence was last collected, whether it is fresh (assessed within 30 days) or stale, and the source connector that produced it.

### Evidence sufficiency scoring

```bash
warlock sufficiency -f soc2
```

Scores each SOC 2 control on evidence sufficiency across four dimensions: volume (enough evidence items), freshness (recently collected), diversity (multiple source types), and assertion coverage. Controls scoring below 60 need attention before the audit.

Focus on gaps:

```bash
warlock sufficiency -f soc2 --below 60
```

### Evidence gaps

```bash
warlock evidence gaps -f soc2
```

Identifies controls with no evidence at all. These are audit blockers and should be addressed first.

### Evidence freshness

```bash
warlock evidence freshness -f soc2
```

Lists controls with stale evidence (older than the configured threshold). For SOC 2 Type II, evidence must cover the observation period. Stale evidence outside the audit window will be rejected by your auditor.

---

## Step 4: Risk Analysis

Quantify the financial impact of non-compliant controls and demonstrate risk management to your auditor.

### FAIR risk quantification

```bash
warlock risk analyze -f soc2
```

Runs a Monte Carlo simulation (10,000 iterations by default) across SOC 2 control gaps. Produces per-scenario results: mean annualized loss expectancy (ALE), Value at Risk at 95th and 99th percentiles, and control effectiveness ratings.

### Risk appetite thresholds

```bash
warlock risk-engine appetite list
```

Displays configured risk appetite thresholds by category. If none are set, define them before the audit:

```bash
warlock risk-engine appetite set --category "access_control" --threshold 500000 --unit USD
```

### Risk report

```bash
warlock reports risk -f soc2
```

Generates a risk summary for SOC 2: top risks by severity, mean exposure, and remediation priority. Suitable for inclusion in the auditor's management representation letter.

---

## Step 5: Gap Remediation

Non-compliant controls need documented remediation plans. Warlock tracks these as issues and POA&Ms with full state machine lifecycle.

### Open issues for SOC 2

```bash
warlock issues -f soc2
```

Lists all open compliance issues scoped to SOC 2. Each issue is linked to a specific control and finding, with priority, assignee, and status. Issues auto-created from non-compliant results include the control ID and failure reason.

### Auto-create issues from failures

```bash
warlock issues-auto-create -f soc2
```

Scans non-compliant SOC 2 control results and creates issues for any that do not already have one. Run this after each pipeline execution to ensure nothing falls through.

### Plans of Action and Milestones

```bash
warlock poams -f soc2
```

Lists POA&Ms for SOC 2 controls: weakness description, severity, due date, delay count, and status (draft, open, in_progress, completed). Auditors will review overdue POA&Ms closely.

Check for overdue items specifically:

```bash
warlock poams --overdue
```

### Compensating controls

```bash
warlock compensating-controls -f soc2
```

Lists alternative controls documented for SOC 2 requirements that cannot be fully met. Each compensating control has an effectiveness score and expiry date.

---

## Step 6: Report Generation

Generate the reports your auditor and management team need.

### Audit readiness assessment

```bash
warlock reports audit-readiness -f soc2
```

A single-screen summary: posture score, total controls, compliant count, not-assessed count, open issues, and stale results. Displays a READY or NOT READY status based on whether the score exceeds 80% with zero open issues and zero stale results.

### Executive summary

```bash
warlock reports executive -f soc2
```

High-level compliance summary formatted for executive stakeholders. Includes posture score, top non-compliant controls, and trend direction.

### Compliance trend

```bash
warlock reports trend -f soc2 --days 90
```

Shows how SOC 2 posture has changed over the last 90 days using posture snapshot history. Type II audits require demonstrated improvement over time; this report provides that evidence.

### Board-level KRI/KPI report

```bash
warlock reports board -f soc2
```

Key Risk Indicators and Key Performance Indicators formatted for board presentations.

---

## Step 7: OSCAL Export

Export machine-readable audit artifacts in OSCAL 1.1.2 format. OSCAL (Open Security Controls Assessment Language) is the NIST standard for structured compliance data exchange.

### Assessment results

```bash
warlock oscal assessment-results soc2
```

Exports all SOC 2 control assessment results as an OSCAL Assessment Results JSON document. Includes every control's status, assessor, timestamp, and finding references.

### System Security Plan

```bash
warlock oscal ssp soc2 --system-name "Acme Production Environment"
```

Exports an OSCAL SSP document for SOC 2. Contains the system description, control implementations, and responsibility assignments.

### POA&M export

```bash
warlock oscal poam -f soc2
```

Exports open POA&Ms as an OSCAL POA&M document with weakness descriptions, milestones, and scheduled completion dates.

### Complete audit package

```bash
warlock oscal audit-package -f soc2 -o ./soc2-audit-package/
```

Generates a complete audit directory containing all OSCAL artifacts:
- `assessment-results.json` -- control assessment outcomes
- `ssp.json` -- System Security Plan
- `poam.json` -- Plans of Action and Milestones
- `component-definition.json` -- system component inventory
- `manifest.json` -- index of all files in the package

Hand this directory to your auditor as the primary evidence package.

---

## Step 8: Ongoing Monitoring

SOC 2 Type II is not a point-in-time assessment. Maintain continuous compliance throughout the observation period.

### Compliance drift detection

```bash
warlock drift -f soc2
```

Shows controls whose status has changed (improved or regressed) over a configurable window. Catch regressions before your auditor does.

### Posture history

```bash
warlock posture-history -f soc2 --days 90
```

Tracks posture score over time for SOC 2. Demonstrates to your auditor that controls were operating effectively throughout the observation period, not just on the day of the audit.

### Coverage summary

```bash
warlock coverage -f soc2
```

Shows overall compliance coverage: how many SOC 2 controls have been assessed, how many are compliant, and the framework-level pass rate.

---

## SOC 2 Control Family Reference

The following table maps SOC 2 Trust Services Criteria families to the data sources Warlock uses for assessment.

| Family | Controls | Category | Key Data Sources |
|--------|----------|----------|-----------------|
| CC1 | CC1.1 -- CC1.5 | Control Environment | SailPoint, Workday, KnowBe4 |
| CC2 | CC2.1 -- CC2.3 | Communication and Information | Splunk, Sentinel, Confluence, ServiceNow |
| CC3 | CC3.1 -- CC3.4 | Risk Assessment | Tenable, Qualys, CrowdStrike, Wiz, Prisma |
| CC4 | CC4.1 -- CC4.2 | Monitoring Activities | AWS Config, SecurityHub, GuardDuty, Wiz |
| CC5 | CC5.1 -- CC5.3 | Control Activities | Prisma, AWS Config, SailPoint, CyberArk |
| CC6 | CC6.1 -- CC6.8 | Logical and Physical Access | IAM, Okta, Entra ID, SailPoint, CrowdStrike |
| CC7 | CC7.1 -- CC7.5 | System Operations | GuardDuty, Splunk, Sentinel, Elastic, Falcon |
| CC8 | CC8.1 | Change Management | CloudTrail, AWS Config, ServiceNow, Entra ID |
| CC9 | CC9.1 -- CC9.2 | Risk Mitigation | Tenable, CrowdStrike, Wiz, SecurityScorecard |
| A1 | A1.1 -- A1.3 | Availability | Prisma, Tenable, CrowdStrike, Veeam |
| C1 | C1.1 -- C1.2 | Confidentiality | S3, Azure Storage, GCS, Prisma |
| PI1 | PI1.1 -- PI1.5 | Processing Integrity | CloudTrail, AWS Config, GCP Audit Logs |
| P1 | P1.0 -- P1.2 | Privacy | OneTrust, Prisma, Confluence |

---

## Auditor Handoff Checklist

Before handing off to your external auditor, verify each item:

1. **Posture score above 80%** -- `warlock reports audit-readiness -f soc2`
2. **Zero overdue POA&Ms** -- `warlock poams -f soc2 --overdue`
3. **No critical open issues** -- `warlock issues -f soc2 --priority critical`
4. **Evidence freshness within observation period** -- `warlock evidence freshness -f soc2`
5. **All controls have evidence** -- `warlock evidence gaps -f soc2`
6. **Sufficiency scores above 60 for all controls** -- `warlock sufficiency -f soc2 --below 60`
7. **OSCAL audit package generated** -- `warlock oscal audit-package -f soc2 -o ./soc2-audit-package/`
8. **Hash chain integrity verified** -- `warlock evidence verify <result-id>` (spot check several controls)
