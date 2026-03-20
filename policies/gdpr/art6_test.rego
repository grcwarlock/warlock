package gdpr.art6_test

import rego.v1

import data.gdpr.art6

test_compliant_lawful_basis if {
	result := art6.result with input as {"normalized_data": {
		"processing_activities": [
			{"name": "payroll", "legal_basis": "contract", "consent_recorded": false},
			{"name": "marketing", "legal_basis": "consent", "consent_recorded": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_legal_basis if {
	result := art6.result with input as {"normalized_data": {
		"processing_activities": [{"name": "analytics", "legal_basis": null}],
	}}
	result.compliant == false
}

test_invalid_legal_basis if {
	result := art6.result with input as {"normalized_data": {
		"processing_activities": [{"name": "tracking", "legal_basis": "business_need"}],
	}}
	result.compliant == false
}

test_consent_not_recorded if {
	result := art6.result with input as {"normalized_data": {
		"processing_activities": [{"name": "newsletter", "legal_basis": "consent", "consent_recorded": false}],
	}}
	result.compliant == false
}
