package iso_27001.a5.a5_31_test

import rego.v1

import data.iso_27001.a5.a5_31

test_compliant_a5_31 if {
	result := a5_31.result with input as {"normalized_data": {
		"audit_manager": {
			"enabled": true,
			"assessments": ["item1"],
		},
		"policies": {
			"legal_requirements_documented": true,
		},
		"security_hub": {
			"enabled_standards": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_31 if {
	result := a5_31.result with input as {"normalized_data": {}}
	result.compliant == false
}
