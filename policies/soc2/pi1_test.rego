package soc2.pi1_test

import rego.v1

import data.soc2.pi1

test_compliant_processing_integrity if {
	result := pi1.result with input as {"normalized_data": {"processing_integrity": {
		"input_validation_enabled": true,
		"processing_monitoring_enabled": true,
		"data_quality_checks_configured": true,
		"error_handling_procedures_exist": true,
		"audit_trail_enabled": true,
		"reconciliation_procedures_exist": true,
		"processing_authorization_required": true,
		"timeliness_sla_defined": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_validation if {
	result := pi1.result with input as {"normalized_data": {"processing_integrity": {}}}
	result.compliant == false
}
