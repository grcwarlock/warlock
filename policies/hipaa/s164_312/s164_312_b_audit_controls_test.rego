package hipaa.s164_312.s164_312_b_test

import rego.v1

import data.hipaa.s164_312.s164_312_b

test_compliant_audit_controls if {
	result := s164_312_b.result with input as {"normalized_data": {
		"config": {
			"audit_logging_enabled": true,
			"log_retention_days": 365,
			"log_monitoring_enabled": true,
		},
		"resources": {"datastores": [
			{"name": "db-prod", "contains_ephi": true, "audit_logging_enabled": true},
		]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_audit_logging if {
	result := s164_312_b.result with input as {"normalized_data": {
		"config": {
			"audit_logging_enabled": false,
			"log_retention_days": 0,
			"log_monitoring_enabled": false,
		},
		"resources": {"datastores": [
			{"name": "db-prod", "contains_ephi": true, "audit_logging_enabled": false},
		]},
	}}
	result.compliant == false
}
