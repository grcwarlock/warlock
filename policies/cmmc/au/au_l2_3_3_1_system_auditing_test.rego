package cmmc.au.au_l2_3_3_1_test

import rego.v1

import data.cmmc.au.au_l2_3_3_1

test_compliant_system_auditing if {
	result := au_l2_3_3_1.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "audit_logging_enabled": true, "log_retention_days": 180, "log_integrity_validation": true},
		],
		"accounts": [
			{"name": "aws-prod", "cloudtrail_enabled": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_audit_logging if {
	result := au_l2_3_3_1.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "audit_logging_enabled": false, "log_retention_days": 0, "log_integrity_validation": false},
		],
		"accounts": [
			{"name": "aws-prod", "cloudtrail_enabled": false},
		],
	}}
	result.compliant == false
}
