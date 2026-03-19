package iso_27001.a8.a8_01_test

import rego.v1

import data.iso_27001.a8.a8_01

test_compliant_a8_01 if {
	result := a8_01.result with input as {"normalized_data": {
		"ssm": {
			"software_inventory_enabled": true,
			"managed_instances": [],
		},
		"users": [],
		"ec2": {
			"instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_01 if {
	result := a8_01.result with input as {"normalized_data": {
		"users": [{"username": "testuser", "console_access": true, "mfa_enabled": false}],
		"ec2": {"instances": [{"id": "i-123", "state": "running", "ssm_managed": false}]},
		"ssm": {"software_inventory_enabled": false, "managed_instances": []},
	}}
	result.compliant == false
}
