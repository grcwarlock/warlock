package nist.ra.ra_7_test

import rego.v1

import data.nist.ra.ra_7

test_compliant_risk_response if {
	result := ra_7.result with input as {"normalized_data": {
		"risk_response": {"response_options_defined": true},
		"identified_risks": [{"id": "R1", "response_selected": "mitigate", "mitigation_implemented": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_response if {
	result := ra_7.result with input as {"normalized_data": {}}
	result.compliant == false
}
