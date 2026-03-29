package warlock.iso_27701.breach_test

import rego.v1

import data.warlock.iso_27701.breach

test_compliant_breach_notification if {
	result := breach.result with input as {"normalized_data": {
		"privacy": {
			"breach_notification_process": true,
			"breach_records_maintained": true,
			"breaches": [
				{"id": "BRK-001", "notification_sent": true, "hours_since_discovery": 24, "impact_assessed": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_late_notification if {
	result := breach.result with input as {"normalized_data": {
		"privacy": {
			"breach_notification_process": true,
			"breach_records_maintained": true,
			"breaches": [
				{"id": "BRK-002", "notification_sent": false, "hours_since_discovery": 96, "impact_assessed": true},
			],
		},
	}}
	result.compliant == false
}

test_no_breach_process if {
	result := breach.result with input as {"normalized_data": {
		"privacy": {
			"breach_notification_process": false,
			"breach_records_maintained": true,
			"breaches": [],
		},
	}}
	result.compliant == false
}

test_no_impact_assessment if {
	result := breach.result with input as {"normalized_data": {
		"privacy": {
			"breach_notification_process": true,
			"breach_records_maintained": true,
			"breaches": [
				{"id": "BRK-003", "notification_sent": true, "hours_since_discovery": 12, "impact_assessed": false},
			],
		},
	}}
	result.compliant == false
}
