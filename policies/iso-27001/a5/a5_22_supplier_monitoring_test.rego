package iso_27001.a5.a5_22_test

import rego.v1

import data.iso_27001.a5.a5_22

test_compliant_a5_22 if {
	result := a5_22.result with input as {"normalized_data": {
		"health": {
			"monitoring_active": true,
		},
		"eventbridge": {
			"health_alert_rule_exists": true,
		},
		"support": {
			"trusted_advisor_enabled": true,
		},
		"policies": {
			"supplier_review_process_documented": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_22 if {
	result := a5_22.result with input as {"normalized_data": {}}
	result.compliant == false
}
