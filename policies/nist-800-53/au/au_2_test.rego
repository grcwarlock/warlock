package nist.au.au_2_test

import rego.v1

import data.nist.au.au_2

test_compliant_aws_logging if {
	result := au_2.result with input as {
		"provider": "aws",
		"normalized_data": {
			"trails": [
				{"name": "main-trail", "is_multi_region": true, "is_logging": true, "log_file_validation_enabled": true},
			],
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_multi_region_trail if {
	result := au_2.result with input as {
		"provider": "aws",
		"normalized_data": {
			"trails": [
				{"name": "local-trail", "is_multi_region": false, "is_logging": true, "log_file_validation_enabled": true},
			],
		},
	}
	result.compliant == false
}
