package nist.sr.sr_2

import rego.v1

# SR-2: Supply Chain Risk Management Plan

deny_no_scrm_plan contains msg if {
	not input.normalized_data.supply_chain_risk_plan
	msg := "SR-2: No supply chain risk management plan developed"
}

deny_plan_not_approved contains msg if {
	plan := input.normalized_data.supply_chain_risk_plan
	not plan.approved
	msg := "SR-2: Supply chain risk management plan has not been approved"
}

deny_plan_outdated contains msg if {
	plan := input.normalized_data.supply_chain_risk_plan
	plan.last_review_days > 365
	msg := sprintf("SR-2: Supply chain risk management plan has not been reviewed in %d days", [plan.last_review_days])
}

deny_no_risk_identification contains msg if {
	plan := input.normalized_data.supply_chain_risk_plan
	not plan.risks_identified
	msg := "SR-2: Supply chain risks have not been identified in the plan"
}

deny_no_mitigation_strategies contains msg if {
	plan := input.normalized_data.supply_chain_risk_plan
	not plan.mitigation_strategies_defined
	msg := "SR-2: No mitigation strategies defined for identified supply chain risks"
}

deny_plan_not_integrated contains msg if {
	plan := input.normalized_data.supply_chain_risk_plan
	not plan.integrated_with_enterprise_risk
	msg := "SR-2: Supply chain risk management plan not integrated with enterprise risk management"
}

default compliant := false

compliant if {
	count(deny_no_scrm_plan) == 0
	count(deny_plan_not_approved) == 0
	count(deny_plan_outdated) == 0
	count(deny_no_risk_identification) == 0
	count(deny_no_mitigation_strategies) == 0
	count(deny_plan_not_integrated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_scrm_plan],
		[f | some f in deny_plan_not_approved],
	),
	array.concat(
		array.concat(
			[f | some f in deny_plan_outdated],
			[f | some f in deny_no_risk_identification],
		),
		array.concat(
			[f | some f in deny_no_mitigation_strategies],
			[f | some f in deny_plan_not_integrated],
		),
	),
)

result := {
	"control_id": "SR-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
