package iso_27001.a5.a5_36_test

import rego.v1

import data.iso_27001.a5.a5_36

test_compliant_a5_36 if {
	result := a5_36.result with input as {"normalized_data": {
		"config": {
			"conformance_packs_exist": true,
			"conformance_packs": [],
			"rules": [],
		},
		"cloudwatch": {
			"compliance_dashboard_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_36 if {
	result := a5_36.result with input as {"normalized_data": {}}
	result.compliant == false
}
