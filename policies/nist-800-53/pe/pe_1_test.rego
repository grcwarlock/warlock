package nist.pe.pe_1_test

import rego.v1

import data.nist.pe.pe_1

test_compliant_pe_policy if {
	result := pe_1.result with input as {"normalized_data": {
		"physical_security": {
			"policy_defined": true,
			"policy_reviewed_within_365_days": true,
			"procedures_documented": true,
			"designated_official": "John Doe",
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_pe_policy if {
	result := pe_1.result with input as {"normalized_data": {
		"physical_security": {"policy_defined": false, "procedures_documented": false, "designated_official": false},
	}}
	result.compliant == false
}
