# Warlock GRC Platform: Risk Management Enhancement Report

**Date:** 2026-03-19
**Scope:** Risk quantification, vendor/third-party risk, operational risk, control effectiveness, predictive capabilities
**Baseline:** Current state of `warlock/assessors/risk_engine.py`, `vendor_risk.py`, `anomaly.py`, `simulation.py`, `drift.py`, `posture.py`, `workflows/risk_acceptance.py`, `workflows/compensating.py`, and related DB models.

---

## Executive Summary

Warlock has a strong risk foundation: FAIR-based Monte Carlo simulation, PERT distributions, posture-driven control effectiveness, vendor risk scoring via SecurityScorecard, compliance drift detection, and a risk acceptance lifecycle. This report identifies 28 specific enhancements across five domains, rated by priority, effort, and business value.

The most impactful gaps are: incomplete FAIR taxonomy coverage (loss magnitude categories missing), no formal risk appetite/tolerance framework, no TPRM lifecycle beyond assessment, no BIA/BCP module, no MTTD/MTTR tracking, and no trend-based predictive risk modeling.

---

## 1. Risk Quantification Enhancements

### 1.1 FAIR Model Completeness

**Current state:** `risk_engine.py` implements the FAIR top-level structure -- Threat Event Frequency (TEF) via PERT-sampled Poisson counts and Loss Magnitude (LM) via PERT-sampled dollar values, modulated by control effectiveness. The `ThreatScenario` dataclass (lines 132-146) captures frequency min/mode/max and impact min/mode/max with a single `control_effectiveness` scalar.

**Gap analysis against full FAIR taxonomy:**

| FAIR Element | Status | Detail |
|---|---|---|
| Loss Event Frequency (LEF) | Partial | TEF is modeled; Vulnerability (probability of action becoming loss) is collapsed into `control_effectiveness` |
| Threat Event Frequency (TEF) | Implemented | PERT distribution with Poisson event counts |
| Contact Frequency | Missing | How often threat agents contact assets -- collapsed into TEF |
| Probability of Action | Missing | Likelihood threat agent acts once contact is made |
| Vulnerability | Partial | `control_effectiveness` conflates Threat Capability and Resistance Strength |
| Threat Capability (TCap) | Missing | Should be a separate distribution reflecting threat agent sophistication |
| Resistance Strength (RS) | Missing | Should derive from control posture but as a separate distribution |
| Loss Magnitude (LM) | Partial | Single impact range; no decomposition into loss categories |
| Primary Loss | Missing | Direct losses (response cost, replacement cost) not separated |
| Secondary Loss | Missing | Indirect losses (fines, reputation, competitive advantage) not separated |

**Recommendation:** Decompose `ThreatScenario` into a richer model:

```
ThreatScenario
  +-- contact_frequency: PERTParams       # NEW
  +-- probability_of_action: PERTParams   # NEW
  +-- threat_capability: PERTParams       # NEW (replaces half of control_effectiveness)
  +-- resistance_strength: PERTParams     # NEW (derived from posture_score)
  +-- primary_loss: LossMagnitude         # NEW (decomposed)
  +-- secondary_loss: LossMagnitude       # NEW (decomposed)
```

**Priority:** P1 | **Effort:** L | **Business value:** High -- proper FAIR taxonomy enables defensible risk conversations with boards and regulators; current single-scalar approach undersells the engine's rigor.

---

### 1.2 Loss Magnitude Categories

**Current state:** Impact is a single `impact_min/mode/max` range in `DEFAULT_SCENARIO_CATALOG` (lines 45-124). The `SimulationResult` returns aggregate ALE/VaR without category breakdown.

**Missing loss categories per FAIR/Open FAIR:**

| Category | Description | Current Coverage |
|---|---|---|
| Productivity | Lost revenue during downtime/disruption | Not tracked |
| Response | IR, forensics, legal, notification costs | Not tracked |
| Replacement | Asset rebuild, data restoration | Not tracked |
| Fines & Judgments | Regulatory penalties, settlements | Not tracked |
| Reputation | Customer churn, brand damage | Not tracked |
| Competitive Advantage | IP loss, market position erosion | Not tracked |

**Recommendation:** Add a `LossMagnitude` dataclass with per-category PERT parameters. Each category gets its own min/mode/max. The simulation sums across categories per event and reports category-level VaR in results. This enables questions like "What is our 95th percentile regulatory fine exposure?"

The `DEFAULT_SCENARIO_CATALOG` should be extended so that, e.g., the `data_exfiltration` scenario for SC controls has high fines/reputation impact while `configuration_drift` for CM has high productivity/replacement but low fines.

**Priority:** P1 | **Effort:** M | **Business value:** High -- loss category breakdown is the #1 thing boards ask for; it directly supports insurance quantification and budget justification.

---

### 1.3 Threat Modeling Integration

**Current state:** `DEFAULT_SCENARIO_CATALOG` maps NIST control families (AC, SI, CP, etc.) to named threat scenarios (unauthorized_access, malware, etc.). There is no STRIDE or MITRE ATT&CK mapping.

**Gaps:**

- **STRIDE:** No systematic categorization of threats as Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. The current scenario names partially overlap (identity_compromise ~ Spoofing, data_exfiltration ~ Information Disclosure) but the mapping is implicit and incomplete.

- **MITRE ATT&CK:** No technique IDs (e.g., T1078 Valid Accounts) linked to scenarios. The connector ecosystem (CrowdStrike, SentinelOne, Defender) ingests ATT&CK-tagged alerts, but this context is lost during normalization.

**Recommendation:**

1. Add `stride_category` and `mitre_techniques: list[str]` fields to `ThreatScenario`.
2. Extend `DEFAULT_SCENARIO_CATALOG` entries with ATT&CK technique mappings -- e.g., `identity_compromise` maps to T1078, T1110, T1556.
3. During normalization, preserve ATT&CK technique IDs from EDR findings (CrowdStrike, SentinelOne, Defender normalizers already parse detection data).
4. Correlate: when a finding arrives tagged with T1078, automatically associate it with the `identity_compromise` scenario for risk quantification.

**Priority:** P2 | **Effort:** M | **Business value:** Medium -- differentiator for security-mature customers; enables "what if Technique X is used against us?" scenario analysis.

---

### 1.4 Risk Appetite/Tolerance Framework

**Current state:** No formal risk appetite or tolerance thresholds exist. The `VendorRiskEngine` has a hardcoded `high_risk_threshold=60.0` (line 353 of `vendor_risk.py`). The `RiskAcceptance` model stores `risk_level` as a string but there is no organizational threshold that defines what "acceptable" means.

**Gap:** Without a risk appetite framework, the platform cannot answer: "Is our current residual risk within acceptable bounds?" or "Which risks exceed our tolerance and require mandatory treatment?"

**Recommendation:** Introduce a `RiskAppetite` configuration model:

```
RiskAppetite:
  framework: str
  risk_category: str          # operational, regulatory, financial, reputational
  appetite_level: str         # aggressive, moderate, conservative, averse
  tolerance_threshold_ale: float   # max acceptable mean ALE
  tolerance_threshold_var95: float # max acceptable VaR at 95%
  escalation_trigger_ale: float    # ALE that triggers board escalation
  owner: str                  # risk owner
  approved_by: str
  effective_date: datetime
  review_date: datetime
```

Wire this into `RiskEngine.analyze_framework_risk()` so the output includes: "3 scenarios exceed risk tolerance; 1 requires board escalation."

**Priority:** P0 | **Effort:** M | **Business value:** Very High -- this is the foundational policy layer that makes all other risk quantification actionable. Without it, ALE numbers are informational only.

---

### 1.5 Risk Treatment Options with Cost-Benefit Analysis

**Current state:** `RiskEngine.compare_treatments()` (lines 455-517) already implements treatment comparison with ROI calculation. Each treatment has `effectiveness_delta` and `cost`, and the engine computes `risk_reduction` and `roi`. This is a solid foundation.

**Gaps:**

- **Treatment type taxonomy:** No classification of treatments as avoid, transfer, mitigate, or accept. The `compare_treatments` method treats everything as mitigation (effectiveness increase).
- **Transfer modeling:** Risk transfer (insurance, contractual indemnity) should reduce loss magnitude rather than increase effectiveness. Insurance has deductibles, coverage limits, and premium costs that require different math.
- **Avoidance modeling:** Eliminating an asset/process removes the scenario entirely. The engine should support "scenario removal" as a treatment option.
- **Accept:** Already modeled via `RiskAcceptance` workflow, but not integrated into `compare_treatments` output.
- **Multi-treatment optimization:** No way to ask "given a $500K budget, what combination of treatments minimizes portfolio VaR?"

**Recommendation:**

1. Add `treatment_type` enum: `avoid | transfer | mitigate | accept`.
2. For `transfer`: model insurance with `premium`, `deductible`, `coverage_limit`, `sublimit_per_event`. Modify loss calculation to apply insurance payout.
3. For `avoid`: allow removing a scenario from portfolio simulation.
4. For `accept`: pull from `RiskAcceptance` records and include residual risk in output.
5. Long-term: add a budget-constrained optimizer that ranks treatments by marginal ROI.

**Priority:** P1 | **Effort:** L | **Business value:** High -- customers need to justify security spend; showing "Option A gives 3.2x ROI vs Option B at 1.1x" is the core value prop of quantified risk.

---

## 2. Vendor/Third-Party Risk

### 2.1 TPRM Lifecycle

**Current state:** `VendorRiskEngine` (vendor_risk.py) handles assessment (scoring) and monitoring (periodic re-scoring with alert creation). The `Vendor` dataclass tracks `last_assessment_date` and `assessment_frequency_days`. There is no onboarding workflow, no offboarding workflow, and no lifecycle state machine.

**Gap:** The TPRM lifecycle should be: Identification -> Due Diligence -> Onboarding -> Ongoing Monitoring -> Reassessment -> Offboarding/Termination. Currently only Ongoing Monitoring and partial Reassessment (via currency scoring) exist.

**Recommendation:** Add a `VendorLifecycle` model:

```
VendorProfile:
  vendor_id: str
  name: str
  lifecycle_status: str  # identified, due_diligence, onboarding, active, under_review,
                         # remediation, offboarding, terminated
  inherent_risk_tier: str  # critical, high, medium, low
  residual_risk_tier: str
  onboarding_date: datetime
  last_assessment_date: datetime
  next_assessment_due: datetime
  offboarding_date: datetime
  data_types_shared: list[str]
  integration_points: list[str]
  contract_expiry: datetime
  primary_contact: str
  risk_owner: str
```

Add lifecycle transition workflows with required gates: e.g., cannot move to `active` without completed due diligence questionnaire and security assessment above threshold.

**Priority:** P1 | **Effort:** L | **Business value:** High -- auditors (SOC 2 CC9.2, ISO 27001 A.5.19-5.22) require documented vendor lifecycle management, not just scoring.

---

### 2.2 Nth-Party Risk (Supply Chain Depth)

**Current state:** The `SA` and `SR` scenario catalog entries (lines 94-105 of risk_engine.py) cover supply chain compromise at a generic level. `UCF-TPM` covers vendor breach. There is no modeling of your vendor's vendors.

**Gap:** If Vendor A depends on Vendor B for hosting, and Vendor B has a breach, your risk exposure is real but invisible. The current model treats each vendor as independent.

**Recommendation:**

1. Add `sub_vendors: list[str]` to `VendorProfile` to track known Nth-party dependencies.
2. Create a vendor dependency graph that can be queried: "Which of our vendors depend on AWS? On Okta?"
3. In `VendorRiskEngine.score_vendor()`, add a sub-vendor risk contribution: if Vendor A's critical sub-vendor has a low security score, Vendor A's score should be penalized.
4. Enable "what if" analysis: "If Okta is compromised, which vendor risk scores change?"

**Priority:** P2 | **Effort:** L | **Business value:** Medium -- regulatory pressure (DORA, OCC guidance) increasingly demands Nth-party visibility, but few customers have sub-vendor data to feed this.

---

### 2.3 Concentration Risk

**Current state:** Not modeled. No mechanism to detect that 15 controls depend on Okta, or that 3 critical vendors all use the same cloud provider.

**Gap:** Concentration risk is invisible. If one vendor/technology/region fails, the blast radius across controls is unknown.

**Recommendation:**

1. Query `ControlResult` to build a provider-to-control dependency map: "Provider X has findings supporting N controls."
2. Add concentration metrics to the vendor risk dashboard: "Single point of failure: Okta appears in 47% of IAM control evidence."
3. Flag when a vendor/provider exceeds a configurable concentration threshold.
4. Integrate with `risk_engine.py` portfolio simulation: concentration means scenarios are correlated, not independent. The current conservative VaR sum (line 428: "assuming perfect positive correlation") is actually correct for concentrated exposures -- but the engine should detect and report when this assumption applies.

**Priority:** P1 | **Effort:** M | **Business value:** High -- concentration risk is a top-3 auditor question and a real operational threat.

---

### 2.4 SLA Compliance Tracking

**Current state:** `VendorRiskEngine._sla_compliance_score()` (lines 221-253) scores three SLA metrics: `uptime_pct`, `response_time_met`, `breach_notification_met`. These are passed in as a dict; there is no persistent SLA tracking, no historical trend, and no automated ingestion.

**Recommendation:**

1. Add a `VendorSLA` model with defined SLA terms per vendor and historical compliance records.
2. Auto-populate from connector data where possible (e.g., ServiceNow uptime, SecurityScorecard breach data).
3. Track SLA compliance trend over time, not just point-in-time.
4. Generate alerts when SLA compliance degrades below contract thresholds.

**Priority:** P2 | **Effort:** M | **Business value:** Medium -- useful for vendor management maturity but not a compliance blocker.

---

### 2.5 Vendor Incident Notification Workflow

**Current state:** `_create_vendor_risk_finding()` (lines 391-465) creates a Finding when a vendor scores below threshold. This flows through the pipeline. However, there is no structured incident notification workflow -- no tracking of "Vendor X notified us of a breach on date Y; here is our response."

**Recommendation:**

1. Add a `VendorIncident` model: `vendor_id`, `incident_type` (breach, outage, compliance_failure), `notification_date`, `response_sla_met`, `impact_assessment`, `remediation_status`.
2. Create a workflow that triggers when a vendor_risk_alert finding is created: assign an owner, set response deadline, track remediation.
3. Integrate with the existing issue tracking model (`Issue` in models.py) so vendor incidents appear in the unified remediation pipeline.

**Priority:** P2 | **Effort:** M | **Business value:** Medium -- SOC 2 and ISO 27001 require documented vendor incident response, and this closes that evidence gap.

---

## 3. Operational Risk

### 3.1 Business Impact Analysis (BIA) Module

**Current state:** No BIA module exists. The `AuditSimulator` (simulation.py) projects compliance posture at future dates but does not assess business impact of system/process failures.

**Gap:** BIA is foundational for BCP/DR and required by NIST CP family controls (CP-2, CP-6 through CP-10), ISO 27001 A.5.29-5.30, and SOC 2 A1.2.

**Recommendation:**

1. Add a `BusinessProcess` model: `name`, `criticality` (mission-critical, business-critical, business-operational, administrative), `rto_hours` (Recovery Time Objective), `rpo_hours` (Recovery Point Objective), `mtpd_hours` (Maximum Tolerable Period of Disruption), `dependencies: list[str]` (other processes, systems, vendors), `annual_revenue_impact`, `regulatory_impact`.
2. Add a `SystemDependency` model linking business processes to system profiles and vendors.
3. Build a BIA scorer that identifies single points of failure and calculates financial impact of downtime.
4. Wire BIA results into risk_engine scenarios: a CP-family scenario's impact_max should come from BIA data, not static catalog values.

**Priority:** P1 | **Effort:** XL | **Business value:** Very High -- BIA is the bridge between technical compliance and business risk language; without it, the platform speaks controls but not business outcomes.

---

### 3.2 Business Continuity Planning Integration

**Current state:** The CP (Contingency Planning) scenario in `DEFAULT_SCENARIO_CATALOG` has hardcoded impact values ($100K-$5M). No BCP plan storage, no plan testing tracking.

**Recommendation:**

1. Add `BCPPlan` model: `business_process_id`, `plan_document_url`, `last_tested`, `test_results`, `next_test_due`, `plan_owner`, `recovery_procedures`.
2. Track BCP plan completeness per business process.
3. Auto-generate CP-family control evidence from BCP plan metadata (plan exists, plan tested within 12 months, etc.).
4. Feed into `AuditSimulator`: if a BCP plan test is due before the audit date, flag it.

**Priority:** P2 | **Effort:** L | **Business value:** Medium -- supports CP control family evidence automation.

---

### 3.3 Disaster Recovery Testing Tracking

**Current state:** No DR test tracking exists.

**Recommendation:** Add a `DRTest` model: `test_date`, `test_type` (tabletop, walkthrough, functional, full), `systems_tested`, `rto_achieved_hours`, `rpo_achieved_hours`, `rto_target_hours`, `rpo_target_hours`, `test_passed: bool`, `findings`, `next_test_due`.

Track whether achieved RTO/RPO meets targets. Generate findings when DR tests fail or are overdue.

**Priority:** P2 | **Effort:** S | **Business value:** Medium -- simple model with high audit evidence value.

---

### 3.4 Key Risk Indicators (KRIs) Dashboard

**Current state:** The platform tracks numerous metrics that could serve as KRIs (posture scores, drift counts, vendor risk scores, anomaly scores, evidence freshness) but does not formalize them as KRIs with thresholds and trend alerting.

**Gap:** KRIs are the operational risk equivalent of KPIs. Without formalized KRIs, risk reporting is ad-hoc.

**Recommendation:**

1. Add a `KRI` configuration model: `name`, `description`, `category` (operational, compliance, vendor, security), `data_source` (which query/metric feeds it), `threshold_green`, `threshold_yellow`, `threshold_red`, `trend_direction` (higher_is_better / lower_is_better), `owner`.
2. Build a KRI evaluation engine that queries current metric values, compares to thresholds, and stores historical values.
3. Seed with default KRIs:
   - Mean posture score (per framework)
   - Count of controls in degraded drift
   - Vendor risk score average
   - Evidence freshness (% of controls with evidence < 30 days old)
   - Open POA&M count by severity
   - Risk acceptance expiry count (next 30 days)
   - Anomaly detection count by severity
4. Expose via API for dashboard consumption.

**Priority:** P1 | **Effort:** M | **Business value:** High -- KRIs are the primary risk communication tool for management and board reporting.

---

### 3.5 Risk Register

**Current state:** `RiskAnalysis` stores per-scenario Monte Carlo results. `RiskAcceptance` tracks accepted risks. `POAM` tracks remediation. But there is no unified risk register that captures strategic, operational, financial, and reputational risks beyond compliance control gaps.

**Gap:** A compliance finding is not the same as a risk. The platform has no place to record "We are expanding into the EU and GDPR enforcement risk increases" or "Key person dependency on the CISO" -- these are enterprise risks that do not map to a specific control failure.

**Recommendation:**

1. Add a `RiskRegister` model: `risk_id`, `title`, `description`, `category` (strategic, operational, compliance, financial, reputational, technology), `likelihood` (rare, unlikely, possible, likely, almost_certain), `impact` (insignificant, minor, moderate, major, catastrophic), `inherent_risk_score`, `control_references: list[str]`, `residual_risk_score`, `risk_owner`, `treatment_plan`, `treatment_type` (avoid, transfer, mitigate, accept), `status` (identified, assessed, treated, monitoring, closed), `review_date`.
2. Link to existing models: a risk register entry can reference `RiskAnalysis` rows (quantified scenario), `RiskAcceptance` rows, and `POAM` rows.
3. Import/export risk register in standard formats (ISO 31000 risk register template).

**Priority:** P1 | **Effort:** M | **Business value:** Very High -- the risk register is the central artifact for risk governance; without it, risk management is fragmented across POA&Ms, acceptances, and analyses.

---

## 4. Control Effectiveness

### 4.1 MTTD and MTTR Tracking

**Current state:** The `ComplianceDrift` model (models.py line 1120) records `detected_at` but does not track when the underlying issue was introduced or when remediation completed. The `Issue` model has lifecycle timestamps but no explicit MTTD/MTTR calculation.

**Gap:** MTTD (time from control failure to detection) and MTTR (time from detection to remediation) are the two most important control effectiveness metrics. They are not computed anywhere.

**Recommendation:**

1. Compute MTTD: compare `ComplianceDrift.detected_at` against the `ChangeEvent.occurred_at` for correlated changes (already captured by `DriftDetector.correlate_changes()`). The delta is MTTD.
2. Compute MTTR: when a `ComplianceDrift` with direction "degraded" is followed by a later drift with direction "improved" for the same control, the delta is MTTR.
3. Store MTTD/MTTR on the `ComplianceDrift` record or in a separate `ControlEffectivenessMetric` table.
4. Aggregate MTTD/MTTR by control family, framework, and time period for trending.
5. Feed into KRI dashboard (see 3.4).

**Priority:** P0 | **Effort:** M | **Business value:** Very High -- MTTD/MTTR are the universal language of security operations and audit committees. The data to compute them already exists; this is wiring, not new collection.

---

### 4.2 Control Failure Rate Trending

**Current state:** `PostureTimeSeriesQuery` (posture.py lines 754-861) computes linear regression slope on posture scores and classifies trend as improving/stable/degrading. `ComplianceDriftDetector` in anomaly.py tracks non-compliance ratio in a sliding window.

**Gap:** These track posture degradation, not control failure rate. A control that flips compliant/non-compliant every week has a 50% failure rate but might show a "stable" trend because the average posture score is unchanged.

**Recommendation:**

1. Define "control failure" as a transition from any compliant state to non_compliant in `ComplianceDrift`.
2. Compute failure rate: failures per time period (monthly, quarterly).
3. Track failure frequency, not just current state.
4. Flag controls with increasing failure frequency even if the latest state is compliant -- these are unreliable controls.

**Priority:** P2 | **Effort:** S | **Business value:** Medium -- identifies controls that appear compliant at point-in-time but are operationally unreliable.

---

### 4.3 Compensating Control Effectiveness Decay

**Current state:** `CompensatingControl` model has `effectiveness_score` (Float, 0-100), `expiry_date`, `review_frequency`, and `last_reviewed`. The `CompensatingControlManager` checks expiry but does not model effectiveness decay over time.

**Gap:** Compensating controls degrade. A compensating control approved 6 months ago at 85% effectiveness may now be at 60% due to environmental changes. There is no mechanism to detect or model this decay.

**Recommendation:**

1. Track `effectiveness_score` history (append to a JSON array or separate table on each review).
2. Apply a configurable decay curve: e.g., linear decay of 2 points per month if no review occurs.
3. Alert when projected effectiveness drops below a threshold (e.g., 50%).
4. Automatically trigger re-review when decay model predicts effectiveness will fall below threshold before next scheduled review.
5. Feed decayed effectiveness into `RiskEngine`: when a compensating control covers a scenario, use the decayed effectiveness, not the approval-time score.

**Priority:** P1 | **Effort:** M | **Business value:** High -- compensating controls are inherently temporary; unmanaged decay creates invisible risk accumulation.

---

### 4.4 Risk Acceptance Re-evaluation Triggers

**Current state:** `RiskAcceptance` has `auto_reeval_triggers` (JSON dict, line 545 of models.py) with suggested keys `severity_change` and `new_finding`. `RiskAcceptanceManager.check_expired()` only checks date expiry. The trigger-based re-evaluation is defined in the schema but never executed.

**Gap:** The data model supports re-evaluation triggers, but no code evaluates them. A risk acceptance approved at "moderate" should be re-evaluated if a new critical finding arrives for the same control, but this does not happen.

**Recommendation:**

1. In the pipeline's post-assessment phase, check whether any new findings affect controls with active risk acceptances.
2. If `auto_reeval_triggers.new_finding` is true and a new finding arrives for the accepted control, set `status` to `under_review` and create an Issue.
3. If `auto_reeval_triggers.severity_change` is true and the finding severity exceeds the accepted `risk_level`, escalate immediately.
4. Add additional trigger types: `posture_score_drop` (posture drops below threshold), `vendor_score_change`, `regulation_change`.

**Priority:** P0 | **Effort:** S | **Business value:** Very High -- this is already designed and stored in the DB; it just needs to be wired. Without it, risk acceptances are "set and forget" -- a major audit finding.

---

## 5. Predictive Capabilities

### 5.1 Trend-Based Risk Prediction

**Current state:** `PostureTimeSeriesQuery._compute_slope()` (posture.py lines 828-861) computes linear regression slope on posture scores. `AuditSimulator` uses this to project scores at target dates (simulation.py lines 134-143). The projection is simple: `projected_score = current + slope * days_ahead`.

**Gap:** The current projection answers "What will the posture score be on date X?" but not "When will this control fail?" or "At current degradation rate, when does VaR exceed risk tolerance?"

**Recommendation:**

1. **Control failure prediction:** Given a degrading trend slope and current posture score, compute `days_to_failure = (current_score - failure_threshold) / abs(slope)`. Surface this in drift reports: "At current rate, AC-2 will breach posture threshold in 47 days."
2. **Portfolio risk projection:** Re-run `RiskEngine.simulate_portfolio()` with projected future posture scores (not current). Compare current portfolio VaR against projected-30/60/90 day VaR.
3. **Confidence intervals:** The linear regression should output R-squared and prediction intervals, not just point estimates. A control with noisy data (low R-squared) should show wide prediction bands.
4. **Non-linear trends:** Support exponential and logistic decay models for controls that degrade faster once they start failing (cascade effects).

**Priority:** P1 | **Effort:** M | **Business value:** High -- transforms the platform from reactive ("what is our risk today?") to proactive ("when will our risk exceed tolerance?").

---

### 5.2 Compliance Deadline Forecasting

**Current state:** `AuditSimulator.simulate()` projects posture at a user-specified target date. `POAM` has `scheduled_completion` and `delay_count`. No forecasting of whether POA&Ms will actually complete on time.

**Recommendation:**

1. Build a POA&M completion predictor based on historical delay patterns: if a POA&M has been delayed twice, the probability of on-time completion is lower.
2. For each open POA&M, compute: `estimated_actual_completion = scheduled_completion + (avg_delay_days * delay_probability)`.
3. Aggregate across frameworks: "At current remediation velocity, 23% of open POA&Ms will miss the audit date."
4. Factor compensating control expiry: if a compensating control expires before the POA&M completes, there is an uncovered gap window.
5. Factor risk acceptance expiry: if a risk acceptance expires before remediation completes, the control reverts to non-compliant.

**Priority:** P2 | **Effort:** M | **Business value:** High -- directly answers the audit readiness question: "Will we be ready?"

---

### 5.3 Resource Allocation Optimization

**Current state:** `RiskEngine.compare_treatments()` computes ROI per treatment. No mechanism to optimize across the full portfolio.

**Gap:** The question is not "What is the ROI of fixing AC-2?" but "Given $200K and 3 FTEs, what should we fix first to maximize risk reduction?"

**Recommendation:**

1. Build a portfolio optimization function: input is a list of possible treatments (each with cost, time, effectiveness_delta) and a budget constraint. Output is the ranked allocation that maximizes total portfolio risk reduction per dollar.
2. Use a greedy knapsack approach (sort by marginal ROI, fill budget) for the initial implementation. This is sufficient for most portfolios.
3. Visualize as a risk reduction waterfall: "Fix X: -$120K ALE, Fix Y: -$80K ALE, Fix Z: -$45K ALE."
4. Integrate with POA&M prioritization: the optimization output should influence which POA&Ms are scheduled first.

**Priority:** P2 | **Effort:** L | **Business value:** High -- the most requested capability from CISOs; turns risk data into actionable investment decisions.

---

## Priority Summary

### P0 -- Must-have, implement immediately

| # | Enhancement | Effort | Business Value |
|---|---|---|---|
| 1.4 | Risk Appetite/Tolerance Framework | M | Very High |
| 4.1 | MTTD/MTTR Tracking | M | Very High |
| 4.4 | Risk Acceptance Re-evaluation Triggers | S | Very High |

**Rationale:** 1.4 makes risk quantification actionable. 4.1 unlocks the most important control effectiveness metric using data already collected. 4.4 is partially implemented -- the schema exists, the code does not.

### P1 -- High priority, next quarter

| # | Enhancement | Effort | Business Value |
|---|---|---|---|
| 1.1 | FAIR Model Completeness | L | High |
| 1.2 | Loss Magnitude Categories | M | High |
| 1.5 | Risk Treatment Options (full taxonomy) | L | High |
| 2.1 | TPRM Lifecycle | L | High |
| 2.3 | Concentration Risk | M | High |
| 3.1 | Business Impact Analysis | XL | Very High |
| 3.4 | KRI Dashboard | M | High |
| 3.5 | Risk Register | M | Very High |
| 4.3 | Compensating Control Effectiveness Decay | M | High |
| 5.1 | Trend-Based Risk Prediction | M | High |

### P2 -- Important, planned

| # | Enhancement | Effort | Business Value |
|---|---|---|---|
| 1.3 | Threat Modeling Integration (STRIDE/ATT&CK) | M | Medium |
| 2.2 | Nth-Party Risk | L | Medium |
| 2.4 | SLA Compliance Tracking | M | Medium |
| 2.5 | Vendor Incident Notification Workflow | M | Medium |
| 3.2 | Business Continuity Planning Integration | L | Medium |
| 3.3 | Disaster Recovery Testing Tracking | S | Medium |
| 4.2 | Control Failure Rate Trending | S | Medium |
| 5.2 | Compliance Deadline Forecasting | M | High |
| 5.3 | Resource Allocation Optimization | L | High |

---

## Implementation Dependencies

Several enhancements chain together. Recommended implementation order within each phase:

**Phase 1 (P0):**
1. Risk Appetite/Tolerance Framework (1.4) -- required by everything that follows
2. Risk Acceptance Re-evaluation Triggers (4.4) -- quick win, schema exists
3. MTTD/MTTR Tracking (4.1) -- data exists, needs computation layer

**Phase 2 (P1, batch A):**
1. Risk Register (3.5) -- foundational model
2. KRI Dashboard (3.4) -- depends on having metrics to track
3. Loss Magnitude Categories (1.2) -- prerequisite for full FAIR
4. FAIR Model Completeness (1.1) -- builds on 1.2

**Phase 2 (P1, batch B):**
1. TPRM Lifecycle (2.1) -- vendor model foundation
2. Concentration Risk (2.3) -- depends on vendor + control mapping
3. Compensating Control Effectiveness Decay (4.3)
4. Trend-Based Risk Prediction (5.1) -- depends on posture time series

**Phase 2 (P1, batch C):**
1. Business Impact Analysis (3.1) -- large effort, can run in parallel
2. Risk Treatment Options (1.5) -- builds on FAIR completeness

---

## Existing Strengths to Preserve

The current risk architecture has notable strengths that any enhancement should maintain:

1. **Pipeline-first design:** Risk quantification flows from posture data, which flows from findings, which flow from connectors. Enhancements should feed into this pipeline, not bypass it.

2. **Zero hard dependencies:** `risk_engine.py` works without numpy (triangular fallback), `anomaly.py` works without sklearn (Z-score/Mahalanobis fallback). New modules should follow this pattern.

3. **Audit trail integrity:** All risk data is persisted with timestamps. New models should follow the same SHA-256 hash chain pattern.

4. **Conservative defaults:** Portfolio VaR assumes perfect positive correlation (worst case). Risk appetite thresholds should default to conservative, not permissive.

5. **Treatment ROI framework:** `compare_treatments()` is already well-designed. Extend it, do not replace it.
