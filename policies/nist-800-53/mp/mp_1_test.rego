package nist.mp.mp_1_test

import rego.v1

import data.nist.mp.mp_1

test_compliant_media_policy if {
	result := mp_1.result with input as {"normalized_data": {
		"media_protection": {
			"policy_defined": true,
			"policy_reviewed_within_365_days": true,
			"procedures_documented": true,
			"designated_official": "Jane Doe",
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_media_policy if {
	result := mp_1.result with input as {"normalized_data": {
		"media_protection": {
			"policy_defined": false,
			"procedures_documented": false,
			"designated_official": false,
		},
	}}
	result.compliant == false
}
