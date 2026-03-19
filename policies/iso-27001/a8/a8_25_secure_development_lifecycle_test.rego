package iso_27001.a8.a8_25_test

import rego.v1

import data.iso_27001.a8.a8_25

test_compliant_a8_25 if {
	result := a8_25.result with input as {"normalized_data": {
		"inspector": {
			"ecr_scanning_enabled": true,
		},
		"codeguru": {
			"reviewer_associated": true,
		},
		"pipelines": [{"name": "main-pipeline", "has_security_stage": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_25 if {
	result := a8_25.result with input as {"normalized_data": {
		"pipelines": [{"name": "main-pipeline", "has_security_stage": false}],
		"inspector": {"ecr_scanning_enabled": false},
		"codeguru": {"reviewer_associated": false},
	}}
	result.compliant == false
}
