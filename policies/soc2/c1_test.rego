package soc2.c1_test

import rego.v1

import data.soc2.c1

test_compliant_confidentiality if {
	result := c1.result with input as {
		"provider": "aws",
		"normalized_data": {"confidentiality": {
			"data_classification_policy_exists": true,
			"storage_resources": [{"name": "bucket1", "encryption_at_rest_enabled": true, "classification": "internal", "public_access_enabled": false}],
			"endpoints": [{"name": "api1", "tls_enabled": true}],
			"dlp_rules_configured": true,
			"retention_policy_exists": true,
			"data_disposal_procedures_exist": true,
		}},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_classification if {
	result := c1.result with input as {
		"provider": "aws",
		"normalized_data": {"confidentiality": {
			"storage_resources": [],
			"endpoints": [],
		}},
	}
	result.compliant == false
}
