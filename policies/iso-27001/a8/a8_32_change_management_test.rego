package iso_27001.a8.a8_32_test

import rego.v1

import data.iso_27001.a8.a8_32

test_compliant_a8_32 if {
	result := a8_32.result with input as {"normalized_data": {
		"config": {
			"stack_drift_rule_exists": true,
			"recorder_enabled": true,
		},
		"cloudformation": {
			"stacks": ["item1"],
		},
		"pipelines": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_32 if {
	result := a8_32.result with input as {"normalized_data": {}}
	result.compliant == false
}
