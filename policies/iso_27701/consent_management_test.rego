package warlock.iso_27701.consent_test

import rego.v1

import data.warlock.iso_27701.consent

test_compliant_consent if {
	result := consent.result with input as {"normalized_data": {
		"privacy": {
			"consent_mechanism_active": true,
			"consent_records_maintained": true,
			"consent_withdrawal_available": true,
			"processing_activities": [
				{"name": "marketing-email", "lawful_basis_documented": true},
			],
			"processing_records_maintained": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_consent_mechanism if {
	result := consent.result with input as {"normalized_data": {
		"privacy": {
			"consent_mechanism_active": false,
			"consent_records_maintained": true,
			"processing_activities": [],
			"processing_records_maintained": true,
		},
	}}
	result.compliant == false
}

test_no_withdrawal if {
	result := consent.result with input as {"normalized_data": {
		"privacy": {
			"consent_mechanism_active": true,
			"consent_records_maintained": true,
			"consent_withdrawal_available": false,
			"processing_activities": [],
			"processing_records_maintained": true,
		},
	}}
	result.compliant == false
}

test_no_lawful_basis if {
	result := consent.result with input as {"normalized_data": {
		"privacy": {
			"consent_mechanism_active": true,
			"consent_records_maintained": true,
			"consent_withdrawal_available": true,
			"processing_activities": [
				{"name": "analytics", "lawful_basis_documented": false},
			],
			"processing_records_maintained": true,
		},
	}}
	result.compliant == false
}
