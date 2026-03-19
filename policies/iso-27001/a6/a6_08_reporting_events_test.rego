package iso_27001.a6.a6_08_test

import rego.v1

import data.iso_27001.a6.a6_08

test_compliant_a6_08 if {
	result := a6_08.result with input as {"normalized_data": {
		"guardduty": {
			"enabled": true,
		},
		"sns": {
			"security_reporting_topic_exists": true,
		},
		"eventbridge": {
			"security_event_notification_rule_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_08 if {
	result := a6_08.result with input as {"normalized_data": {}}
	result.compliant == false
}
