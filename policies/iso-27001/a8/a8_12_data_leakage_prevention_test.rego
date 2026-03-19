package iso_27001.a8.a8_12_test

import rego.v1

import data.iso_27001.a8.a8_12

test_compliant_a8_12 if {
	result := a8_12.result with input as {"normalized_data": {
		"macie": {
			"enabled": true,
		},
		"s3": {
			"account_public_access_blocked": true,
			"buckets": [],
		},
		"organization": {
			"data_exfiltration_scp_exists": true,
		},
		"vpc_endpoints": ["item1"],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_12 if {
	result := a8_12.result with input as {"normalized_data": {}}
	result.compliant == false
}
