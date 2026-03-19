package iso_27001.a8.a8_31_test

import rego.v1

import data.iso_27001.a8.a8_31

test_compliant_a8_31 if {
	result := a8_31.result with input as {"normalized_data": {
		"organization": {
			"separate_accounts_per_environment": true,
			"env_separation_scp_exists": true,
		},
		"vpcs": [],
		"resources": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_31 if {
	result := a8_31.result with input as {"normalized_data": {}}
	result.compliant == false
}
