package ucf.gov.ucf_gov_1_test

import rego.v1

import data.ucf.gov.ucf_gov_1

test_policy_exists_and_current if {
	result := ucf_gov_1.result with input as {"normalized_data": {
		"policies": {"information_security_policy": {
			"exists": true,
			"approved": true,
			"last_review_days": 30,
			"communicated": true,
		}},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_policy if {
	result := ucf_gov_1.result with input as {"normalized_data": {"policies": {}}}
	result.compliant == false
}

test_policy_outdated if {
	result := ucf_gov_1.result with input as {"normalized_data": {
		"policies": {"information_security_policy": {
			"exists": true,
			"approved": true,
			"last_review_days": 400,
			"communicated": true,
		}},
	}}
	result.compliant == false
}
