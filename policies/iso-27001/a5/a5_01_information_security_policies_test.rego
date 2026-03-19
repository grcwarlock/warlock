package iso_27001.a5.a5_01_test

import rego.v1

import data.iso_27001.a5.a5_01

test_compliant_a5_01 if {
	result := a5_01.result with input as {"normalized_data": {
		"policies": {
			"information_security_policy": {
				"approved": true,
				"last_review_days": 30,
				"communicated": true,
			},
		},
		"organization": {
			"scp_policies_exist": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_01 if {
	result := a5_01.result with input as {"normalized_data": {}}
	result.compliant == false
}
