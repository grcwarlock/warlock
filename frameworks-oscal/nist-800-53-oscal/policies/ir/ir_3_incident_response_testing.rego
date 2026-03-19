package nist.ir.ir_3

import rego.v1

# IR-3: Incident Response Testing
# Validates incident response testing and exercises are conducted

deny_no_ir_testing contains msg if {
	not input.normalized_data.ir_testing
	msg := "IR-3: No incident response testing program configured"
}

deny_testing_overdue contains msg if {
	input.normalized_data.ir_testing
	input.normalized_data.ir_testing.last_test_days > 365
	msg := sprintf("IR-3: Incident response testing is overdue (%d days since last test, exceeds annual requirement)", [input.normalized_data.ir_testing.last_test_days])
}

deny_no_test_results contains msg if {
	input.normalized_data.ir_testing
	not input.normalized_data.ir_testing.results_documented
	msg := "IR-3: Incident response test results are not documented"
}

deny_no_tabletop_exercise contains msg if {
	input.normalized_data.ir_testing
	not input.normalized_data.ir_testing.tabletop_exercise_conducted
	msg := "IR-3: No tabletop exercise conducted for incident response testing"
}

deny_lessons_not_incorporated contains msg if {
	input.normalized_data.ir_testing
	input.normalized_data.ir_testing.results_documented
	not input.normalized_data.ir_testing.lessons_incorporated
	msg := "IR-3: Lessons learned from IR testing have not been incorporated into procedures"
}

deny_no_coordination_tested contains msg if {
	input.normalized_data.ir_testing
	not input.normalized_data.ir_testing.coordination_tested
	msg := "IR-3: Coordination with related plans and external parties has not been tested"
}

default compliant := false

compliant if {
	count(deny_no_ir_testing) == 0
	count(deny_testing_overdue) == 0
	count(deny_no_test_results) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_testing],
		[f | some f in deny_testing_overdue],
	),
	array.concat(
		[f | some f in deny_no_test_results],
		array.concat(
			[f | some f in deny_no_tabletop_exercise],
			array.concat(
				[f | some f in deny_lessons_not_incorporated],
				[f | some f in deny_no_coordination_tested],
			),
		),
	),
)

result := {
	"control_id": "IR-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
