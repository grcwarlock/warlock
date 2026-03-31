# AI-GRC Integration Brief

**Date:** 2026-03-20
**Scope:** AI reasoning integration across all Warlock GRC workflows
**Principle:** Every AI capability has a deterministic fallback. AI is an enhancer, never a gatekeeper. The toggle is per-tenant, per-workflow.

---

## 1. Remediation Intelligence

### Current State

`remediation_loader.py` serves 1,779 static YAML entries keyed by `(framework, control_id)`. Each entry contains a `summary`, `remediation_steps` list, and `console_path`. The loader attaches guidance to `ControlResult` rows only when the assertion engine did not already provide remediation. There is no awareness of the customer's environment, no prioritization logic, and no tracking of whether remediation was actually executed.

### AI-On Behavior

**Environment-specific remediation plans.** When AI is enabled, the remediation engine receives the finding's normalized data (`FindingData`), the static KB entry, and the customer's infrastructure context (cloud provider, resource tags, deployment model from `SystemProfile`, connected tooling from active connectors). The LLM produces a remediation plan that references the customer's actual resource IDs, console paths for their specific cloud provider, and CLI commands with the correct region and account context. The plan is structured JSON, not free text: `steps[]` where each step has `action`, `target_resource`, `command_or_path`, `verification_check`, and `estimated_effort_minutes`.

**Risk-weighted prioritization.** Cross-reference the `RiskEngine` simulation results for the control family. A non-compliant AC-2 with a $2.3M mean ALE gets different urgency language than a non-compliant PE-1 with a $45K mean ALE. The AI receives the Monte Carlo output (mean ALE, VaR-95, control effectiveness score) and produces a prioritization narrative: "This remediation reduces your identity_compromise scenario's VaR-95 from $1.8M to $620K based on raising AC-family control effectiveness from 0.35 to 0.85."

**Remediation plan generation for POA&M items.** When a POA&M is auto-created from a non-compliant result, the AI generates a multi-phase remediation plan with milestones that map to the POA&M's `scheduled_completion`. Each milestone has a verification assertion that can be checked automatically on the next pipeline run. The plan becomes the POA&M's `implementation_plan` field.

**Remediation tracking intelligence.** On each pipeline cycle, the AI compares previous remediation guidance against current finding state. If the finding persists unchanged after two cycles, the AI escalates with alternative approaches. If the finding partially resolved (e.g., 80% of resources now encrypted, 20% remain), it acknowledges progress and narrows guidance to remaining resources.

### Deterministic Fallback (AI-Off)

Static KB lookup as implemented today. Remediation steps from YAML, no environment context, no prioritization beyond severity. POA&M items get the `weakness_description` from the assertion engine but no structured plan. No cross-referencing with risk engine output.

---

## 2. Risk Analysis

### Current State

`risk_engine.py` implements a FAIR Monte Carlo engine with PERT distributions, 13 threat scenarios mapped to NIST control families, portfolio simulation with conservative VaR aggregation, treatment comparison with ROI calculation, DB-backed caching with posture-hash invalidation, and loss exceedance curves. The engine is purely quantitative. It produces numbers but no interpretation.

### AI-On Behavior

**Scenario generation from findings.** Instead of relying solely on the static `DEFAULT_SCENARIO_CATALOG` keyed by control family, the AI analyzes the actual finding population. If the pipeline shows 47 unpatched critical CVEs across 12 hosts in the DMZ, the AI generates a targeted scenario: "DMZ exploitation via unpatched Apache Struts (CVE-2025-XXXX)" with frequency and impact parameters calibrated to the specific vulnerability's EPSS score and the organization's exposure surface. These AI-generated scenarios feed into the same `simulate_scenario()` path as static ones.

**Narrative risk reports.** After simulation completes, the AI receives the portfolio output (per-scenario mean ALE, VaR percentiles, exceedance curves, control effectiveness scores) and produces three report tiers:

1. **Technical risk report** -- per-scenario breakdown with statistical detail, treatment recommendations with ROI, control effectiveness gaps. Audience: security engineers and GRC analysts.
2. **Insurance-ready summary** -- aggregate ALE and VaR figures, loss exceedance curves described in actuarial language, control maturity assessment, claims history correlation points. Format matches what cyber insurance underwriters expect in applications and renewals. Audience: risk management, CFO, insurance brokers.
3. **Board-level briefing** -- three to five bullet points: total annualized risk exposure, top three scenarios by VaR-95, quarter-over-quarter trend (improving/degrading), one recommended investment with projected risk reduction. No jargon. Dollar figures only. Audience: board of directors, executive committee.

**What-if scenario modeling.** The AI generates treatment scenarios based on the current gap analysis. "If you implement MFA across all privileged accounts (AC-2 effectiveness from 0.35 to 0.90), your identity_compromise VaR-95 drops from $1.8M to $420K. Estimated implementation cost: $180K/year. ROI: 7.7x." These feed into the existing `compare_treatments()` method.

**Correlation-aware portfolio aggregation.** The current engine sums VaR across scenarios assuming perfect positive correlation (conservative upper bound). The AI can suggest correlation adjustments based on the finding population: "Your AC and IA scenarios share the same root cause (no MFA), so their correlation should be near 1.0. Your CP and PE scenarios are largely independent." This advisory does not replace the deterministic calculation but annotates it.

### Deterministic Fallback (AI-Off)

Monte Carlo simulation runs exactly as today. Static scenario catalog, PERT distributions, portfolio aggregation with perfect-correlation assumption. No narrative reports -- raw JSON with numbers. No AI-generated scenarios. Treatment comparison available but requires manual scenario definition.

---

## 3. Compliance Assessment

### Current State

`ai_reasoning.py` provides Tier 2 assessment: when deterministic assertions are unavailable or inconclusive, an LLM evaluates a finding against a control using the full compliance context (compensating controls, risk acceptances, inheritance, posture trends, monitoring cadence, drift history). The system prompt enforces structured JSON output with status, assessment narrative, confidence score, and context factors. Four LLM providers are supported (Anthropic, OpenAI, Gemini, Ollama) with prompt hashing for reproducibility.

`governance_analyzer.py` performs deterministic governance document analysis: staleness detection, policy area keyword matching, control reference extraction, obligation language strength scoring, and TF-IDF comprehensiveness scoring.

### AI-On Behavior

**Cross-framework gap analysis.** The AI receives the full control result set across all 14 frameworks and identifies crosswalk gaps: "You are compliant with NIST AC-2 but non-compliant with the equivalent SOC 2 CC6.1. The gap is that your access review evidence satisfies NIST's requirement for periodic review but lacks the user-level recertification documentation that SOC 2 auditors expect." This uses the existing crosswalk data in the framework YAMLs but applies GRC reasoning to explain why technically-equivalent controls can have different compliance statuses.

**Evidence sufficiency evaluation.** For each control result, the AI evaluates whether the underlying evidence would satisfy a skeptical auditor. Not "is the control technically compliant?" (that is what assertions do) but "would the evidence we have survive an audit?" Questions it answers: Is the evidence timely (within the monitoring frequency)? Is it complete (covers all in-scope resources)? Is it authentic (hash-chained, from a trusted source)? Is it relevant (does it actually prove what the control requires)? Output: evidence sufficiency score (0.0-1.0) per control, with specific gaps identified.

**Continuous monitoring intelligence.** Beyond the cadence staleness check that already exists in `ComplianceContext`, the AI identifies patterns in drift history. "AC-2 has drifted non-compliant three times in the last 90 days, each time within 48 hours of the monthly access review. Root cause hypothesis: new hire provisioning workflow bypasses the access review gate. Recommended: increase monitoring frequency to weekly and add a pre-provisioning assertion." This turns reactive drift detection into proactive monitoring tuning.

**Audit preparation intelligence.** The AI generates a per-framework audit readiness score based on: evidence coverage (percentage of controls with recent evidence), evidence sufficiency (would it survive auditor scrutiny), policy coverage (from `GovernanceAnalyzer`), POA&M status (open items, overdue items, extension history), and compensating control health (approaching expiry, effectiveness scores). This is a composite score with drill-down, not a single number.

**Governance document deep analysis.** Extend `GovernanceAnalyzer` with AI: instead of TF-IDF similarity, the LLM reads the actual policy document content and evaluates whether the language is enforceable (obligation strength), whether the scope covers the control requirement, whether the document addresses the specific technical implementation details the framework expects, and whether there are contradictions between policies.

### Deterministic Fallback (AI-Off)

Tier 1 assertions run as today. Tier 2 AI reasoning is skipped; inconclusive controls get `not_assessed` status. Governance analysis uses TF-IDF and keyword matching only. No cross-framework gap narrative. No evidence sufficiency evaluation beyond cadence staleness. No audit readiness composite score.

---

## 4. Questionnaire and Trust Portal

### Current State

`questionnaires.py` implements a full questionnaire lifecycle with SIG Lite and DDQ templates, status machine transitions, risk scoring, and two levels of auto-response:

1. `ai_suggest_answers()` -- simple control result lookup by mapped control IDs, produces yes/no or text with confidence percentage.
2. `auto_respond()` -- keyword-matched evidence from `ControlResult.assertion_name` and `Finding.title`, produces richer answers with evidence snippets and remediation references.

Both approaches are keyword-based. Neither understands the question's intent, and neither can compose a narrative answer that would satisfy a sophisticated customer reviewing the questionnaire.

### AI-On Behavior

**Context-aware narrative answers.** The AI receives the question text, the mapped controls, the full evidence corpus (not just keyword matches but the actual finding details, assertion results, policy documents, and posture scores), and generates a response that reads like a knowledgeable security engineer wrote it. For "Do you enforce multi-factor authentication for all user accounts?": instead of "Yes, pipeline evidence" the response becomes "Yes. MFA is enforced for all user accounts via Okta conditional access policies. Our most recent assessment (2026-03-18) confirmed 100% MFA enrollment across 847 active user accounts. Admin accounts additionally require hardware security keys (FIDO2). Evidence: IAM connector assessment results for controls IA-2, IA-2(1), IA-2(2)."

**Confidence scoring with explanation.** Each AI-generated answer gets a structured confidence breakdown: control coverage (what percentage of mapped controls have compliant results), evidence freshness (how recent is the evidence), evidence depth (assertion-backed vs. finding-only vs. no evidence), and known gaps (any mapped controls that are non-compliant or not assessed). The reviewer sees both the answer and the reasoning behind the confidence score.

**Reviewer suggestions.** For answers where confidence is below a configurable threshold (e.g., 70%), the AI flags them for human review with specific guidance: "This answer claims 'Yes' based on 2 of 3 mapped controls being compliant, but NIST SC-28 (encryption at rest) shows non-compliant for 3 S3 buckets. Reviewer should verify whether these buckets are in scope for this vendor relationship before confirming the response."

**Custom questionnaire ingestion.** When a customer sends a non-standard questionnaire (not SIG Lite or DDQ), the AI parses the questions, maps them to the closest framework controls, and auto-generates a template. The mapping is presented for human review before auto-response runs.

**Trust portal SOC 2 report Q&A.** When a prospective customer views the SOC 2 report on the trust portal and submits follow-up questions, the AI answers from the report content and underlying evidence. "Your SOC 2 report mentions compensating controls for CC6.7 -- can you elaborate?" The AI pulls the actual compensating control record and explains it in context.

### Deterministic Fallback (AI-Off)

Keyword-matched auto-response as implemented in `auto_respond()`. Yes/no answers based on compliant vs. non-compliant control count. Text answers composed from evidence snippet concatenation. No narrative composition, no confidence breakdown, no reviewer suggestions, no custom questionnaire ingestion.

---

## 5. Evidence Intelligence

### Current State

`evidence_retention.py` manages SOC 2 Type II evidence snapshots: snapshot creation with SHA-256 hash signing, period verification (monthly evidence coverage per control), and gap detection. Evidence quality is measured only by presence/absence per month. There is no evaluation of whether the evidence actually proves what it claims.

### AI-On Behavior

**Evidence content evaluation.** For each evidence artifact, the AI evaluates four dimensions:

1. **Relevance** -- Does this evidence actually demonstrate what the control requires? A screenshot of an S3 bucket's encryption settings is relevant for SC-28. A screenshot of the S3 console landing page is not. The AI reads the evidence content (finding detail, raw event data) against the control description and scores relevance 0.0-1.0.

2. **Completeness** -- Does the evidence cover all in-scope resources? If the control requires encryption at rest for all data stores, but the evidence only covers RDS instances and misses S3 and DynamoDB, the AI identifies the gap. It cross-references the asset inventory (from connectors) against the evidence population.

3. **Timeliness** -- Beyond the simple cadence staleness check, the AI evaluates whether the evidence timing aligns with the audit period. For SOC 2 Type II, evidence must demonstrate continuous operation. A single point-in-time snapshot in month 6 of a 12-month audit period is insufficient even if it is within the monitoring cadence.

4. **Authenticity** -- The AI verifies the evidence chain: raw event has SHA-256 hash, finding was derived from that raw event, control result was derived from that finding. Any broken links in the chain are flagged. This is a deterministic check that the AI contextualizes: "The hash chain for this evidence is intact, but the raw event was ingested 72 hours after the finding's observed_at timestamp, suggesting delayed collection."

**Policy document sufficiency.** For governance controls (the `-1` family in NIST), the AI reads the actual policy document content (from Confluence findings) and evaluates whether it is sufficient for the specific control. Not just "does an access control policy exist?" but "does the access control policy cover privileged access management, access review frequency, automated enforcement, and termination procedures as required by AC-1?"

**Evidence preparation for audit.** Before an audit, the AI reviews the entire evidence package and produces a readiness report: which controls have sufficient evidence, which need additional collection, which have evidence that is technically valid but may raise auditor questions (e.g., too many exceptions, compensating controls nearing expiry, evidence from a single source without corroboration).

### Deterministic Fallback (AI-Off)

Evidence retention verification as implemented today: monthly presence/absence per control, SHA-256 hash on snapshots, gap detection by month. No content evaluation, no completeness assessment, no sufficiency analysis. Governance analysis limited to TF-IDF scoring and keyword matching from `GovernanceAnalyzer`.

---

## 6. Audit Readiness

### Current State

No dedicated audit readiness module. The components exist in pieces: `evidence_retention.py` checks evidence coverage, `governance_analyzer.py` checks policy coverage, `poam.py` tracks open remediation items, `compensating.py` tracks alternative controls. None of these are synthesized into an audit readiness view.

### AI-On Behavior

**Mock audit questions.** The AI generates realistic auditor questions based on the framework, the organization's specific compliance posture, and known audit focus areas. For SOC 2: "Walk me through how a new employee gets access to production systems. What approvals are required? How is access removed when they leave?" For each question, the AI identifies which evidence artifacts answer it and grades the answer's strength.

**Auditor perspective simulation.** The AI role-plays as a skeptical auditor reviewing the evidence package. It identifies:

- Controls where the evidence is technically valid but an auditor would ask follow-up questions (e.g., a compensating control that has been extended three times).
- Areas where the organization's narrative does not match the evidence (e.g., the SSP says "quarterly access reviews" but the evidence shows reviews only in Q1 and Q3).
- Common audit findings for similar organizations (based on the framework, industry vertical, and deployment model from `SystemProfile`).

**Evidence gap remediation plan.** For each identified gap, the AI produces a specific action: which connector needs to run, which resource needs to be scanned, which policy document needs to be updated, or which process needs to execute before the audit. Each action has an estimated time to complete and a priority based on the auditor's likely focus areas.

**Audit timeline management.** Given an audit start date, the AI works backward to produce a preparation timeline: "8 weeks out: run full evidence collection across all connectors. 6 weeks out: resolve all critical POA&M items. 4 weeks out: complete policy review cycle. 2 weeks out: run mock audit questions and address gaps. 1 week out: freeze evidence package and generate snapshots."

**Historical audit finding correlation.** If the organization has previous audit findings (stored as POA&M items or in a findings archive), the AI identifies which current gaps match previous findings. Recurring findings are flagged with higher severity because auditors track repeat observations.

### Deterministic Fallback (AI-Off)

No mock questions, no auditor simulation, no preparation timeline. Evidence gaps are identified by the existing `get_evidence_gaps()` method (presence/absence by month). Policy gaps from `identify_policy_gaps()` (missing, stale, unreviewed). Open POA&Ms from `list_poams(overdue=True)`. The user manually synthesizes these into an audit preparation plan.

---

## 7. Executive Reporting

### Current State

No dedicated reporting module. Data exists in the database: posture scores, risk analysis results, POA&M statistics, evidence coverage, policy gaps. Exporting this data into executive-consumable formats requires manual effort.

### AI-On Behavior

**Board-ready compliance posture narrative.** The AI synthesizes across all frameworks into a single executive summary: "Warlock monitors compliance across 14 frameworks covering 1,996 controls. Current aggregate posture: 87.3% compliant, 4.2% non-compliant, 8.5% partial. Quarter-over-quarter trend: +2.1 percentage points. Three frameworks require attention: HIPAA (dropped 3.4 points due to new PHI handling findings), PCI DSS (annual recertification due in 45 days with 6 open items), and CMMC L2 (new DFARS requirements added 12 controls not yet assessed)."

**Risk-to-business translation.** Takes the Monte Carlo output and translates it: "Our total annualized risk exposure is $4.2M (90th percentile: $8.7M). The top contributor is identity compromise at $1.8M mean ALE, driven by incomplete MFA deployment across 23% of privileged accounts. A $180K investment in enterprise MFA would reduce this to $420K, yielding a 7.7x return."

**Trend analysis with causal attribution.** The AI does not just report that compliance improved 2.1 points. It explains why: "The improvement is attributable to three factors: (1) completion of the encryption-at-rest remediation project covering 142 S3 buckets (+0.8 points), (2) resolution of 14 overdue POA&M items from the Q3 audit (+0.7 points), and (3) deployment of automated access review via the Okta connector (+0.6 points)."

**Regulatory change impact assessment.** When framework YAMLs are updated with new controls or requirements, the AI assesses the impact: "The NIST 800-53 Rev 6 update adds 14 new controls and modifies 23 existing ones. Based on your current control implementations, 8 new controls are already partially covered by existing compensating controls. 6 require new implementation. Estimated effort: 240 person-hours. Estimated risk reduction: $320K in mean ALE."

**Report generation formats.** The AI produces structured output that can be rendered into:

- PDF executive summary (via the existing binder/export pipeline)
- Slide deck outline (key metrics, trend charts, top risks, recommended actions)
- Email digest (weekly or monthly compliance posture update for stakeholders)
- OSCAL assessment results with narrative annotations

### Deterministic Fallback (AI-Off)

Raw data export only. Posture scores as numbers, risk figures as JSON, POA&M counts as tables. No narrative, no causal attribution, no trend explanation, no regulatory impact assessment. The existing OSCAL exporter produces valid but unannotated assessment results.

---

## Implementation Architecture

### AI Toggle Design

The AI toggle is a per-tenant configuration with per-workflow granularity:

```
ai_enabled: true                    # master toggle
ai_workflows:
  remediation: true                 # environment-specific remediation
  risk_narrative: true              # narrative risk reports
  compliance_assessment: true       # Tier 2 AI reasoning (already exists)
  questionnaire: true               # AI-composed answers
  evidence_evaluation: true         # evidence quality assessment
  audit_readiness: true             # mock audit, gap analysis
  executive_reporting: true         # narrative reports
```

When `ai_enabled` is false, all AI features fall back to deterministic behavior. When `ai_enabled` is true but a specific workflow is false, only that workflow falls back.

### Prompt Safety

All AI integrations follow the existing pattern from `ai_reasoning.py`:

- Evidence data wrapped in `<evidence>` tags with explicit instruction not to interpret content as instructions.
- Control character stripping via `_sanitize_field()`.
- Field truncation at `_MAX_FIELD_LEN` (2,000 characters).
- Prompt hashing (SHA-256) for reproducibility tracking.
- Structured JSON output with validation against known schemas.
- Confidence floor enforcement (default 0.7) -- AI outputs below the floor are treated as `not_assessed`.

### Caching and Cost Control

AI calls are expensive. Every AI-enhanced workflow should:

1. Check whether deterministic methods produce a sufficient result first (e.g., if the assertion engine gives a clear pass/fail, skip AI reasoning).
2. Cache AI outputs with the same posture-hash strategy used by the risk engine. The cache key is a hash of the input data; if the inputs have not changed, serve the cached response.
3. Batch questions where possible (e.g., send all questionnaire questions in one prompt rather than 20 separate calls).
4. Track token usage per workflow per tenant for cost attribution.

### Audit Trail

Every AI-generated output is stored with:

- `prompt_hash`: SHA-256 of the full prompt (already implemented in `ai_reasoning.py`).
- `model`: which LLM model produced the output.
- `confidence`: the AI's self-assessed confidence.
- `deterministic_fallback_available`: whether a non-AI result exists for comparison.
- `human_reviewed`: boolean, initially false, set to true when a human accepts or modifies the output.

AI outputs never override deterministic results without human review. They are presented alongside deterministic results as supplementary intelligence.
