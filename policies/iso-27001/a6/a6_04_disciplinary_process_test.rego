package iso_27001.a6.a6_04_test

import rego.v1

import data.iso_27001.a6.a6_04

test_compliant_a6_04 if {
	result := a6_04.result with input as {"normalized_data": {
		"policies": {
			"disciplinary_policy_documented": true,
		},
		"cloudtrail": {
			"enabled": true,
		},
		"guardduty": {
			"enabled": true,
		},
		"cloudwatch": {
			"unauthorized_access_alarm_exists": true,
		},
		"eventbridge": {
			"policy_violation_rule_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_04 if {
	result := a6_04.result with input as {"normalized_data": {}}
	result.compliant == false
}
