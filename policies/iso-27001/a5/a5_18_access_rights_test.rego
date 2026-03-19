package iso_27001.a5.a5_18_test

import rego.v1

import data.iso_27001.a5.a5_18

test_compliant_a5_18 if {
	result := a5_18.result with input as {"normalized_data": {
		"config": {
			"unused_credentials_rule_exists": true,
		},
		"policies": {
			"access_review_process_documented": true,
		},
		"users": [],
		"access_analyzer": {
			"findings": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_18 if {
	result := a5_18.result with input as {"normalized_data": {}}
	result.compliant == false
}
