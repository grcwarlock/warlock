package nist.pm.pm_8

import rego.v1

# PM-8: Critical Infrastructure Plan

deny_no_cip contains msg if {
	not input.normalized_data.critical_infrastructure_plan
	msg := "PM-8: No critical infrastructure plan established"
}

deny_cip_not_aligned contains msg if {
	cip := input.normalized_data.critical_infrastructure_plan
	not cip.aligned_with_national_strategy
	msg := "PM-8: Critical infrastructure plan is not aligned with national critical infrastructure strategy"
}

deny_cip_no_key_resources contains msg if {
	cip := input.normalized_data.critical_infrastructure_plan
	not cip.key_resources_identified
	msg := "PM-8: Critical infrastructure plan does not identify key resources and essential missions"
}

deny_cip_outdated contains msg if {
	cip := input.normalized_data.critical_infrastructure_plan
	cip.last_review_days > 365
	msg := sprintf("PM-8: Critical infrastructure plan has not been reviewed in %d days", [cip.last_review_days])
}

deny_cip_no_protection_strategy contains msg if {
	cip := input.normalized_data.critical_infrastructure_plan
	not cip.protection_strategy_defined
	msg := "PM-8: Critical infrastructure plan does not define a protection strategy"
}

default compliant := false

compliant if {
	count(deny_no_cip) == 0
	count(deny_cip_not_aligned) == 0
	count(deny_cip_no_key_resources) == 0
	count(deny_cip_outdated) == 0
	count(deny_cip_no_protection_strategy) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_cip],
		[f | some f in deny_cip_not_aligned],
	),
	array.concat(
		[f | some f in deny_cip_no_key_resources],
		array.concat(
			[f | some f in deny_cip_outdated],
			[f | some f in deny_cip_no_protection_strategy],
		),
	),
)

result := {
	"control_id": "PM-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
