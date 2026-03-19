package nist.cp.cp_4

import rego.v1

# CP-4: Contingency Plan Testing
# Validates contingency plan testing schedule and results

deny_no_plan_testing contains msg if {
	not input.normalized_data.contingency_plan_testing
	msg := "CP-4: No contingency plan testing program configured"
}

deny_testing_overdue contains msg if {
	input.normalized_data.contingency_plan_testing
	input.normalized_data.contingency_plan_testing.last_test_days > 365
	msg := sprintf("CP-4: Contingency plan testing is overdue (%d days since last test, exceeds annual requirement)", [input.normalized_data.contingency_plan_testing.last_test_days])
}

deny_no_test_results contains msg if {
	input.normalized_data.contingency_plan_testing
	not input.normalized_data.contingency_plan_testing.results_documented
	msg := "CP-4: Contingency plan test results are not documented"
}

deny_deficiencies_not_addressed contains msg if {
	input.normalized_data.contingency_plan_testing
	input.normalized_data.contingency_plan_testing.open_deficiencies > 0
	msg := sprintf("CP-4: %d deficiencies identified during contingency plan testing remain unaddressed", [input.normalized_data.contingency_plan_testing.open_deficiencies])
}

deny_no_tabletop_exercise contains msg if {
	input.normalized_data.contingency_plan_testing
	not input.normalized_data.contingency_plan_testing.tabletop_exercise_conducted
	msg := "CP-4: No tabletop exercise conducted as part of contingency plan testing"
}

deny_plan_not_updated_after_test contains msg if {
	input.normalized_data.contingency_plan_testing
	input.normalized_data.contingency_plan_testing.results_documented
	not input.normalized_data.contingency_plan_testing.plan_updated_after_test
	msg := "CP-4: Contingency plan has not been updated based on test results"
}

default compliant := false

compliant if {
	count(deny_no_plan_testing) == 0
	count(deny_testing_overdue) == 0
	count(deny_no_test_results) == 0
	count(deny_deficiencies_not_addressed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_plan_testing],
		[f | some f in deny_testing_overdue],
	),
	array.concat(
		[f | some f in deny_no_test_results],
		array.concat(
			[f | some f in deny_deficiencies_not_addressed],
			array.concat(
				[f | some f in deny_no_tabletop_exercise],
				[f | some f in deny_plan_not_updated_after_test],
			),
		),
	),
)

result := {
	"control_id": "CP-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
