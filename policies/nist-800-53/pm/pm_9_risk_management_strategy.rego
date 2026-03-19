package nist.pm.pm_9

import rego.v1

# PM-9: Risk Management Strategy

deny_no_risk_strategy contains msg if {
	not input.normalized_data.risk_management_strategy
	msg := "PM-9: No organization-wide risk management strategy established"
}

deny_no_risk_tolerance contains msg if {
	rms := input.normalized_data.risk_management_strategy
	not rms.risk_tolerance_defined
	msg := "PM-9: Organizational risk tolerance levels have not been defined"
}

deny_strategy_not_approved contains msg if {
	rms := input.normalized_data.risk_management_strategy
	not rms.approved_by_leadership
	msg := "PM-9: Risk management strategy has not been approved by senior leadership"
}

deny_strategy_outdated contains msg if {
	rms := input.normalized_data.risk_management_strategy
	rms.last_review_days > 365
	msg := sprintf("PM-9: Risk management strategy has not been reviewed in %d days", [rms.last_review_days])
}

deny_no_risk_framework contains msg if {
	rms := input.normalized_data.risk_management_strategy
	not rms.risk_framework_adopted
	msg := "PM-9: No risk management framework formally adopted"
}

deny_no_risk_communication contains msg if {
	rms := input.normalized_data.risk_management_strategy
	not rms.risk_communication_plan
	msg := "PM-9: No risk communication plan established for sharing risk information"
}

default compliant := false

compliant if {
	count(deny_no_risk_strategy) == 0
	count(deny_no_risk_tolerance) == 0
	count(deny_strategy_not_approved) == 0
	count(deny_strategy_outdated) == 0
	count(deny_no_risk_framework) == 0
	count(deny_no_risk_communication) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_strategy],
		[f | some f in deny_no_risk_tolerance],
	),
	array.concat(
		array.concat(
			[f | some f in deny_strategy_not_approved],
			[f | some f in deny_strategy_outdated],
		),
		array.concat(
			[f | some f in deny_no_risk_framework],
			[f | some f in deny_no_risk_communication],
		),
	),
)

result := {
	"control_id": "PM-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
