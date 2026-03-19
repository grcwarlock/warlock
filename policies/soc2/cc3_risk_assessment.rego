package soc2.cc3

import rego.v1

# SOC 2 CC3: Risk Assessment (COSO Principles 6-9)
# Risk identification, fraud risk, change identification

deny_no_risk_assessment contains msg if {
	not input.normalized_data.governance.risk_assessment_performed
	msg := "CC3.1: No risk assessment performed — objectives and risk tolerances not defined"
}

deny_stale_risk_assessment contains msg if {
	input.normalized_data.governance.risk_assessment_performed
	input.normalized_data.governance.risk_assessment_age_days > 365
	msg := sprintf("CC3.1: Risk assessment is %d days old — must be reviewed at least annually", [input.normalized_data.governance.risk_assessment_age_days])
}

deny_empty_risk_register contains msg if {
	input.normalized_data.governance.risk_register_entries == 0
	msg := "CC3.2: Risk register is empty — no risks identified across the entity"
}

deny_unmitigated_high_risks contains msg if {
	some risk in input.normalized_data.governance.risks
	risk.severity == "high"
	not risk.mitigation_plan_exists
	msg := sprintf("CC3.2: High-severity risk '%s' has no mitigation plan", [risk.name])
}

deny_no_fraud_risk_assessment contains msg if {
	not input.normalized_data.governance.fraud_risk_assessment_exists
	msg := "CC3.3: No fraud risk assessment — management override, unauthorized access, and data manipulation risks not evaluated"
}

deny_no_fraud_controls contains msg if {
	input.normalized_data.governance.fraud_risk_assessment_exists
	not input.normalized_data.governance.fraud_controls_implemented
	msg := "CC3.3: Fraud risk assessment exists but fraud-specific controls not implemented"
}

deny_no_change_risk_tracking contains msg if {
	not input.normalized_data.governance.change_risk_tracking_enabled
	msg := "CC3.4: No process to identify and assess changes that could significantly impact internal controls"
}

default compliant := false

compliant if {
	count(deny_no_risk_assessment) == 0
	count(deny_stale_risk_assessment) == 0
	count(deny_empty_risk_register) == 0
	count(deny_unmitigated_high_risks) == 0
	count(deny_no_fraud_risk_assessment) == 0
	count(deny_no_fraud_controls) == 0
	count(deny_no_change_risk_tracking) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_risk_assessment],
			[f | some f in deny_stale_risk_assessment],
		),
		array.concat(
			[f | some f in deny_empty_risk_register],
			[f | some f in deny_unmitigated_high_risks],
		),
	),
	array.concat(
		[f | some f in deny_no_fraud_risk_assessment],
		array.concat(
			[f | some f in deny_no_fraud_controls],
			[f | some f in deny_no_change_risk_tracking],
		),
	),
)

result := {
	"control_id": "CC3",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
