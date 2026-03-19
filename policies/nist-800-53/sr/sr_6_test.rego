package nist.sr.sr_6_test

import rego.v1

import data.nist.sr.sr_6

test_compliant_assessments if {
	result := sr_6.result with input as {"normalized_data": {
		"supplier_assessments": true,
		"suppliers": [{"name": "sup1", "is_critical": true, "assessment_completed": true, "days_since_assessment": 100, "risk_rating_assigned": true, "risk_rating": "low"}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_assessments if {
	result := sr_6.result with input as {"normalized_data": {}}
	result.compliant == false
}
