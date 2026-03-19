package iso_27001.a5.a5_21_test

import rego.v1

import data.iso_27001.a5.a5_21

test_compliant_a5_21 if {
	result := a5_21.result with input as {"normalized_data": {
		"inspector": {
			"ecr_scanning_enabled": true,
		},
		"codeartifact": {
			"repositories_exist": true,
		},
		"ecr": {
			"repositories": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_21 if {
	result := a5_21.result with input as {"normalized_data": {}}
	result.compliant == false
}
