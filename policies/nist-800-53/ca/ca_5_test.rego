package nist.ca.ca_5_test

import rego.v1

import data.nist.ca.ca_5

test_compliant_poam if {
	result := ca_5.result with input as {"normalized_data": {
		"poam": {
			"last_updated_days": 10,
			"overdue_milestones": 0,
			"items": [
				{"risk_level": "low", "status": "closed", "age_days": 5, "description": "Fix patch", "responsible_party": "ops", "scheduled_completion_date": "2025-12-01"},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_poam if {
	result := ca_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
