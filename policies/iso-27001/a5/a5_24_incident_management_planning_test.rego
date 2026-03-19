package iso_27001.a5.a5_24_test

import rego.v1

import data.iso_27001.a5.a5_24

test_compliant_a5_24 if {
	result := a5_24.result with input as {"normalized_data": {
		"guardduty": {
			"enabled": true,
		},
		"security_hub": {
			"enabled": true,
		},
		"sns": {
			"security_incident_topic_exists": true,
		},
		"eventbridge": {
			"high_severity_finding_rule_exists": true,
		},
		"ssm": {
			"ir_automation_documents_exist": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_24 if {
	result := a5_24.result with input as {"normalized_data": {}}
	result.compliant == false
}
