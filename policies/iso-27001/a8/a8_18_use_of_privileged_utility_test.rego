package iso_27001.a8.a8_18_test

import rego.v1

import data.iso_27001.a8.a8_18

test_compliant_a8_18 if {
	result := a8_18.result with input as {"normalized_data": {
		"ssm": {
			"session_logging_enabled": true,
		},
		"eventbridge": {
			"privileged_action_rule_exists": true,
		},
		"iam": {
			"deny_privileged_utilities_policy_exists": true,
			"roles": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_18 if {
	result := a8_18.result with input as {"normalized_data": {}}
	result.compliant == false
}
