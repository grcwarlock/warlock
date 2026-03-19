package nist.sa.sa_20_test

import rego.v1

import data.nist.sa.sa_20

test_compliant_custom_dev if {
	result := sa_20.result with input as {"normalized_data": {"customized_development": {
		"critical_components_identified": true,
		"reimplementation_plan": true,
		"last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_custom_dev if {
	result := sa_20.result with input as {"normalized_data": {}}
	result.compliant == false
}
