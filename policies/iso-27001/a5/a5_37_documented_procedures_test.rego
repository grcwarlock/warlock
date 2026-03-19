package iso_27001.a5.a5_37_test

import rego.v1

import data.iso_27001.a5.a5_37

test_compliant_a5_37 if {
	result := a5_37.result with input as {"normalized_data": {
		"ssm": {
			"operational_runbooks_exist": true,
			"documents": [],
		},
		"policies": {
			"operating_procedures_stored": true,
			"operating_procedures": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_37 if {
	result := a5_37.result with input as {"normalized_data": {}}
	result.compliant == false
}
