package iso_27001.a7.a7_02_test

import rego.v1

import data.iso_27001.a7.a7_02

test_compliant_a7_02 if {
	result := a7_02.result with input as {"normalized_data": {
		"cloudtrail": {
			"enabled": true,
			"is_logging": true,
			"log_file_validation_enabled": true,
		},
		"cloudwatch": {
			"console_signin_alarm_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_02 if {
	result := a7_02.result with input as {"normalized_data": {}}
	result.compliant == false
}
