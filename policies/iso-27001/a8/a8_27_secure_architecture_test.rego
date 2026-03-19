package iso_27001.a8.a8_27_test

import rego.v1

import data.iso_27001.a8.a8_27

test_compliant_a8_27 if {
	result := a8_27.result with input as {"normalized_data": {
		"security_hub": {
			"enabled": true,
			"enabled_standards": ["item1"],
		},
		"config": {
			"conformance_packs_exist": true,
		},
		"wellarchitected": {
			"workloads": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_27 if {
	result := a8_27.result with input as {"normalized_data": {}}
	result.compliant == false
}
