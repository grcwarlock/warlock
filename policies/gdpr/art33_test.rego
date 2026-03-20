package gdpr.art33_test

import rego.v1

import data.gdpr.art33

test_compliant_breach_notification if {
	result := art33.result with input as {"normalized_data": {
		"siem": {"active": true, "days_since_rule_review": 30},
		"policies": {"breach_notification_procedure": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_siem if {
	result := art33.result with input as {"normalized_data": {
		"siem": {"active": false},
		"policies": {"breach_notification_procedure": true},
	}}
	result.compliant == false
}

test_no_breach_procedure if {
	result := art33.result with input as {"normalized_data": {
		"siem": {"active": true, "days_since_rule_review": 10},
		"policies": {"breach_notification_procedure": false},
	}}
	result.compliant == false
}

test_stale_detection_rules if {
	result := art33.result with input as {"normalized_data": {
		"siem": {"active": true, "days_since_rule_review": 120},
		"policies": {"breach_notification_procedure": true},
	}}
	result.compliant == false
}
