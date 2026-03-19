package nist.sa.sa_21_test

import rego.v1

import data.nist.sa.sa_21

test_compliant_dev_screening if {
	result := sa_21.result with input as {"normalized_data": {
		"developer_screening": {
			"screening_criteria_defined": true,
			"last_review_days": 100,
		},
		"developers": [{"name": "dev1", "has_privileged_access": true, "background_check_completed": true, "is_contractor": true, "screening_verified": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_screening if {
	result := sa_21.result with input as {"normalized_data": {}}
	result.compliant == false
}
