package nist.cp.cp_1_test

import rego.v1

import data.nist.cp.cp_1

test_compliant_cp_policy if {
	result := cp_1.result with input as {"normalized_data": {
		"contingency_policy": {
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

test_noncompliant_no_cp_policy if {
	result := cp_1.result with input as {"normalized_data": {}}
	result.compliant == false
}
