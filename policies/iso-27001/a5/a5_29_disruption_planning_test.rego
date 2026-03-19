package iso_27001.a5.a5_29_test

import rego.v1

import data.iso_27001.a5.a5_29

test_compliant_a5_29 if {
	result := a5_29.result with input as {"normalized_data": {
		"cloudtrail": {
			"is_multi_region": true,
		},
		"guardduty": {
			"enabled_all_regions": true,
		},
		"s3": {
			"security_config_replicated": true,
		},
		"policies": {
			"business_continuity_plan_documented": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_29 if {
	result := a5_29.result with input as {"normalized_data": {}}
	result.compliant == false
}
