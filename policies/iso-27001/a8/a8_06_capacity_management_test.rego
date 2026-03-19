package iso_27001.a8.a8_06_test

import rego.v1

import data.iso_27001.a8.a8_06

test_compliant_a8_06 if {
	result := a8_06.result with input as {"normalized_data": {
		"cloudwatch": {
			"capacity_alarms_configured": true,
		},
		"compute_optimizer": {
			"enabled": true,
		},
		"autoscaling": {
			"groups": ["item1"],
		},
		"ec2": {
			"instance_count": 0,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_06 if {
	result := a8_06.result with input as {"normalized_data": {}}
	result.compliant == false
}
