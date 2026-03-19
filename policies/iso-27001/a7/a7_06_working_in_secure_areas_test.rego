package iso_27001.a7.a7_06_test

import rego.v1

import data.iso_27001.a7.a7_06

test_compliant_a7_06 if {
	result := a7_06.result with input as {"normalized_data": {
		"iam": {
			"restricted_access_policies_exist": true,
			"secure_area_access_group_exists": true,
			"roles": [],
		},
		"ssm": {
			"session_logging_enabled": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_06 if {
	result := a7_06.result with input as {"normalized_data": {}}
	result.compliant == false
}
