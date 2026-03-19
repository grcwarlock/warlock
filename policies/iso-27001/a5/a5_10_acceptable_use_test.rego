package iso_27001.a5.a5_10_test

import rego.v1

import data.iso_27001.a5.a5_10

test_compliant_a5_10 if {
	result := a5_10.result with input as {"normalized_data": {
		"organization": {
			"region_restriction_scp_exists": true,
			"scps": ["item1"],
		},
		"policies": {
			"acceptable_use_policy": true,
		},
		"config": {
			"allowed_instance_types_rule_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_10 if {
	result := a5_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
