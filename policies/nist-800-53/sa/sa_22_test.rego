package nist.sa.sa_22_test

import rego.v1

import data.nist.sa.sa_22

test_compliant_unsupported if {
	result := sa_22.result with input as {"normalized_data": {
		"unsupported_components": {"last_review_days": 30},
		"system_components": [{"name": "comp1", "version": "1.0", "end_of_life": false, "days_to_eol": 365}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_tracking if {
	result := sa_22.result with input as {"normalized_data": {}}
	result.compliant == false
}
