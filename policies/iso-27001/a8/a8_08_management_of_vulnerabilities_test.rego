package iso_27001.a8.a8_08_test

import rego.v1

import data.iso_27001.a8.a8_08

test_compliant_a8_08 if {
	result := a8_08.result with input as {"normalized_data": {
		"inspector": {
			"enabled": true,
			"ec2_scanning_enabled": true,
			"critical_finding_count": 0,
		},
		"ssm": {
			"patch_baseline_configured": true,
			"managed_instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_08 if {
	result := a8_08.result with input as {"normalized_data": {}}
	result.compliant == false
}
