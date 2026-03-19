package iso_27001.a8.a8_33_test

import rego.v1

import data.iso_27001.a8.a8_33

test_compliant_a8_33 if {
	result := a8_33.result with input as {"normalized_data": {
		"macie": {
			"test_data_scanned": true,
		},
		"config": {
			"test_environment_tags_rule_exists": true,
		},
		"resources": [],
		"rds": {
			"instances": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_33 if {
	result := a8_33.result with input as {"normalized_data": {
		"resources": [{"id": "res-123", "tags": {"Environment": "Test"}}],
		"rds": {"instances": [{"identifier": "test-db", "tags": {"Environment": "Test"}}]},
		"macie": {"enabled": true, "test_data_scanned": false},
		"config": {"test_environment_tags_rule_exists": false},
	}}
	result.compliant == false
}
