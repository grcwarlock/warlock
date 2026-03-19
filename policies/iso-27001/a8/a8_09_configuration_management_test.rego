package iso_27001.a8.a8_09_test

import rego.v1

import data.iso_27001.a8.a8_09

test_compliant_a8_09 if {
	result := a8_09.result with input as {"normalized_data": {
		"config": {
			"recorder_enabled": true,
			"is_recording": true,
			"conformance_packs_exist": true,
			"rules": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_09 if {
	result := a8_09.result with input as {"normalized_data": {}}
	result.compliant == false
}
