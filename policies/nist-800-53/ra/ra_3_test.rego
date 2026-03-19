package nist.ra.ra_3_test

import rego.v1

import data.nist.ra.ra_3

test_compliant_risk_assessment if {
	result := ra_3.result with input as {"normalized_data": {"risk_assessment": {
		"last_assessment_days": 100,
		"threats_identified": true,
		"vulnerabilities_identified": true,
		"likelihood_determined": true,
		"impact_analyzed": true,
		"results_shared_with_stakeholders": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_assessment if {
	result := ra_3.result with input as {"normalized_data": {}}
	result.compliant == false
}
