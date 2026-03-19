package nist.ca.ca_3_test

import rego.v1

import data.nist.ca.ca_3

test_compliant_interconnections if {
	result := ca_3.result with input as {"normalized_data": {
		"system_interconnections": [
			{"source_system": "sys-a", "target_system": "sys-b", "authorized": true, "agreement_expiry_days": 180, "security_requirements_documented": true, "encrypted": true, "last_review_days": 100},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unauthorized_connection if {
	result := ca_3.result with input as {"normalized_data": {
		"system_interconnections": [
			{"source_system": "sys-a", "target_system": "sys-b", "authorized": false},
		],
	}}
	result.compliant == false
}
