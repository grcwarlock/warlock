package nist.at.at_1_test

import rego.v1

import data.nist.at.at_1

test_compliant_training_policy if {
	result := at_1.result with input as {"normalized_data": {
		"training_policy": {
			"exists": true,
			"last_review_days": 100,
			"designated_official": "Jane Doe",
			"scope_defined": true,
			"disseminated": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_training_policy if {
	result := at_1.result with input as {"normalized_data": {}}
	result.compliant == false
}
