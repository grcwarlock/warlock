package iso_27001.a5.a5_32_test

import rego.v1

import data.iso_27001.a5.a5_32

test_compliant_a5_32 if {
	result := a5_32.result with input as {"normalized_data": {
		"macie": {
			"enabled": true,
			"custom_data_identifiers": ["item1"],
		},
		"license_manager": {
			"tracking_active": true,
		},
		"codecommit": {
			"repositories": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_32 if {
	result := a5_32.result with input as {"normalized_data": {}}
	result.compliant == false
}
