package iso_27001.a5.a5_35_test

import rego.v1

import data.iso_27001.a5.a5_35

test_compliant_a5_35 if {
	result := a5_35.result with input as {"normalized_data": {
		"audit_manager": {
			"enabled": true,
			"assessments": ["item1"],
			"assessment_reports": ["item1"],
		},
		"security_hub": {
			"cis_benchmark_enabled": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_35 if {
	result := a5_35.result with input as {"normalized_data": {}}
	result.compliant == false
}
