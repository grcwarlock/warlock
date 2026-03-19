package nist.ra.ra_1_test

import rego.v1

import data.nist.ra.ra_1

test_compliant_policy if {
	result := ra_1.result with input as {"normalized_data": {"risk_assessment_policy": {
		"approved": true,
		"last_review_days": 100,
		"procedures_documented": true,
		"procedures_last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_policy if {
	result := ra_1.result with input as {"normalized_data": {}}
	result.compliant == false
}
