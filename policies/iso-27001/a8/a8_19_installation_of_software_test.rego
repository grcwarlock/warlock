package iso_27001.a8.a8_19_test

import rego.v1

import data.iso_27001.a8.a8_19

test_compliant_a8_19 if {
	result := a8_19.result with input as {"normalized_data": {
		"ssm": {
			"software_inventory_enabled": true,
		},
		"config": {
			"approved_amis_rule_exists": true,
		},
		"ec2": {
			"instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_19 if {
	result := a8_19.result with input as {"normalized_data": {}}
	result.compliant == false
}
