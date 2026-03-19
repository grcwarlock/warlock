package iso_27001.a5.a5_23_test

import rego.v1

import data.iso_27001.a5.a5_23

test_compliant_a5_23 if {
	result := a5_23.result with input as {"normalized_data": {
		"controltower": {
			"landing_zone_deployed": true,
		},
		"security_hub": {
			"enabled": true,
		},
		"organization": {
			"guardrail_scps_attached": true,
		},
		"cloudtrail": {
			"organization_trail_enabled": true,
			"is_multi_region": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_23 if {
	result := a5_23.result with input as {"normalized_data": {}}
	result.compliant == false
}
