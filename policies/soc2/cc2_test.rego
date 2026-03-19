package soc2.cc2_test

import rego.v1

import data.soc2.cc2

test_compliant_communication if {
	result := cc2.result with input as {"normalized_data": {"governance": {
		"internal_communication_policy_exists": true,
		"system_description_documented": true,
		"control_responsibilities_communicated": true,
		"external_communication_policy_exists": true,
		"system_boundaries_defined": true,
		"whistleblower_channel_exists": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_internal_policy if {
	result := cc2.result with input as {"normalized_data": {"governance": {}}}
	result.compliant == false
}
