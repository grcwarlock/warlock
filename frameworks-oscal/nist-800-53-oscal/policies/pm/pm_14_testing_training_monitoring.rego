package nist.pm.pm_14

import rego.v1

# PM-14: Testing, Training, and Monitoring

deny_no_ttm_process contains msg if {
	not input.normalized_data.testing_training_monitoring
	msg := "PM-14: No organization-wide testing, training, and monitoring process established"
}

deny_no_security_testing contains msg if {
	ttm := input.normalized_data.testing_training_monitoring
	not ttm.security_testing_conducted
	msg := "PM-14: Security control testing has not been conducted"
}

deny_testing_outdated contains msg if {
	ttm := input.normalized_data.testing_training_monitoring
	ttm.last_test_days > 365
	msg := sprintf("PM-14: Security control testing has not been conducted in %d days", [ttm.last_test_days])
}

deny_no_training_program contains msg if {
	ttm := input.normalized_data.testing_training_monitoring
	not ttm.training_program_established
	msg := "PM-14: Security training program has not been established"
}

deny_no_monitoring_strategy contains msg if {
	ttm := input.normalized_data.testing_training_monitoring
	not ttm.monitoring_strategy_defined
	msg := "PM-14: Continuous monitoring strategy has not been defined"
}

deny_no_remediation_tracking contains msg if {
	ttm := input.normalized_data.testing_training_monitoring
	not ttm.remediation_tracking
	msg := "PM-14: No process for tracking remediation of testing findings"
}

deny_testing_gaps contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.security_testing_completed
	msg := sprintf("PM-14: System '%s' has not completed required security control testing", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_ttm_process) == 0
	count(deny_no_security_testing) == 0
	count(deny_testing_outdated) == 0
	count(deny_no_training_program) == 0
	count(deny_no_monitoring_strategy) == 0
	count(deny_no_remediation_tracking) == 0
	count(deny_testing_gaps) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ttm_process],
		[f | some f in deny_no_security_testing],
	),
	array.concat(
		array.concat(
			[f | some f in deny_testing_outdated],
			[f | some f in deny_no_training_program],
		),
		array.concat(
			[f | some f in deny_no_monitoring_strategy],
			array.concat(
				[f | some f in deny_no_remediation_tracking],
				[f | some f in deny_testing_gaps],
			),
		),
	),
)

result := {
	"control_id": "PM-14",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
