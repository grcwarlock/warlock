package iso_27001.a5.a5_08_test

import rego.v1

import data.iso_27001.a5.a5_08

test_compliant_a5_08 if {
	result := a5_08.result with input as {"normalized_data": {
		"inspector": {
			"ecr_scanning_enabled": true,
		},
		"codebuild": {
			"security_scan_projects_exist": true,
		},
		"pipelines": [{"name": "main-pipeline", "stages": [{"name": "Security-Scan"}]}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_08 if {
	result := a5_08.result with input as {"normalized_data": {}}
	result.compliant == false
}
