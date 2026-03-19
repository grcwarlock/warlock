package iso_27001.a8.a8_17_test

import rego.v1

import data.iso_27001.a8.a8_17

test_compliant_a8_17 if {
	result := a8_17.result with input as {"normalized_data": {
		"ssm": {
			"ntp_check_commands_executed": true,
			"ntp_config_document_exists": true,
		},
		"ec2": {
			"instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_17 if {
	result := a8_17.result with input as {"normalized_data": {}}
	result.compliant == false
}
