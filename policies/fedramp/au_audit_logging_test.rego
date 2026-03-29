package warlock.fedramp.au_test

import rego.v1

import data.warlock.fedramp.au

test_compliant_audit if {
	result := au.result with input as {"normalized_data": {
		"audit": {
			"sample_records": [
				{"id": "rec-1", "timestamp": "2025-01-01T00:00:00Z", "user_identity": "alice"},
			],
			"regular_review_enabled": true,
			"time_synchronization_enabled": true,
			"tamper_protection_enabled": true,
			"retention_days": 365,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_insufficient_retention if {
	result := au.result with input as {"normalized_data": {
		"audit": {
			"sample_records": [],
			"regular_review_enabled": true,
			"time_synchronization_enabled": true,
			"tamper_protection_enabled": true,
			"retention_days": 90,
		},
	}}
	result.compliant == false
}

test_no_tamper_protection if {
	result := au.result with input as {"normalized_data": {
		"audit": {
			"sample_records": [],
			"regular_review_enabled": true,
			"time_synchronization_enabled": true,
			"tamper_protection_enabled": false,
			"retention_days": 365,
		},
	}}
	result.compliant == false
}

test_missing_timestamp if {
	result := au.result with input as {"normalized_data": {
		"audit": {
			"sample_records": [{"id": "rec-1", "user_identity": "bob"}],
			"regular_review_enabled": true,
			"time_synchronization_enabled": true,
			"tamper_protection_enabled": true,
			"retention_days": 365,
		},
	}}
	result.compliant == false
}
