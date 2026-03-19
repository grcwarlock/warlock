package iso_27001.a7.a7_07_test

import rego.v1

import data.iso_27001.a7.a7_07

test_compliant_a7_07 if {
	result := a7_07.result with input as {"normalized_data": {
		"iam": {
			"password_policy": true,
			"roles": [],
		},
		"organization": {
			"session_duration_scp_exists": true,
		},
		"policies": {
			"clear_desk_policy_documented": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_07 if {
	result := a7_07.result with input as {"normalized_data": {}}
	result.compliant == false
}
