package nist.ma.ma_1_test

import rego.v1

import data.nist.ma.ma_1

test_compliant_maintenance_policy if {
	result := ma_1.result with input as {"normalized_data": {
		"maintenance": {
			"policy_defined": true,
			"policy_reviewed_within_365_days": true,
			"procedures_documented": true,
			"designated_official": "John Doe",
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_policy if {
	result := ma_1.result with input as {"normalized_data": {
		"maintenance": {
			"policy_defined": false,
			"procedures_documented": false,
			"designated_official": false,
		},
	}}
	result.compliant == false
}
