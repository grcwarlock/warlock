package nist.ca.ca_6_test

import rego.v1

import data.nist.ca.ca_6

test_compliant_authorization if {
	result := ca_6.result with input as {"normalized_data": {
		"system_authorization": {
			"authorizing_official": "John Doe",
			"expiry_days": 365,
			"boundary_defined": true,
			"significant_change_detected": false,
			"reauthorization_initiated": false,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_authorization if {
	result := ca_6.result with input as {"normalized_data": {}}
	result.compliant == false
}
