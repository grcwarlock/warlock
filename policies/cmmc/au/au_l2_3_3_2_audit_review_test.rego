package cmmc.au.au_l2_3_3_2_test

import rego.v1

import data.cmmc.au.au_l2_3_3_2

test_compliant_audit_review if {
	result := au_l2_3_3_2.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "audit_logging_enabled": true, "log_monitoring_enabled": true, "security_alerting_configured": true, "processes_cui": true, "siem_integrated": true},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_log_monitoring if {
	result := au_l2_3_3_2.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "audit_logging_enabled": true, "log_monitoring_enabled": false, "security_alerting_configured": false, "processes_cui": true, "siem_integrated": false},
	]}}
	result.compliant == false
}
