package iso_27001.a7.a7_13_test

import rego.v1

import data.iso_27001.a7.a7_13

test_compliant_a7_13 if {
	result := a7_13.result with input as {"normalized_data": {
		"ssm": {
			"maintenance_windows_configured": true,
			"patch_baseline_configured": true,
			"managed_instances": [],
		},
		"ec2": {
			"instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_13 if {
	result := a7_13.result with input as {"normalized_data": {}}
	result.compliant == false
}
