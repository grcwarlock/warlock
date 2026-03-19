package iso_27001.a5.a5_04_test

import rego.v1

import data.iso_27001.a5.a5_04

test_compliant_a5_04 if {
	result := a5_04.result with input as {"normalized_data": {
		"config": {
			"conformance_packs_exist": true,
			"conformance_packs": [],
		},
		"security_hub": {
			"enabled": true,
			"enabled_standards": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_04 if {
	result := a5_04.result with input as {"normalized_data": {}}
	result.compliant == false
}
