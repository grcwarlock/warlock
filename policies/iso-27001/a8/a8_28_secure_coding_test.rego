package iso_27001.a8.a8_28_test

import rego.v1

import data.iso_27001.a8.a8_28

test_compliant_a8_28 if {
	result := a8_28.result with input as {"normalized_data": {
		"codeguru": {
			"reviewer_associated": true,
			"critical_recommendation_count": 0,
		},
		"codebuild": {
			"security_scan_projects_exist": true,
		},
		"ecr": {
			"repositories": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_28 if {
	result := a8_28.result with input as {"normalized_data": {}}
	result.compliant == false
}
