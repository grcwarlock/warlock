package gdpr.art5_test

import rego.v1

import data.gdpr.art5

test_compliant_processing_principles if {
	result := art5.result with input as {"normalized_data": {
		"privacy": {"lawful_basis_documented": true, "purpose_documented": true},
		"storage_resources": [{"name": "db-prod", "encryption_enabled": true}],
		"dlp": {"policies_active": true},
		"policy_documents": [{"name": "Privacy Policy", "days_since_review": 100}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_lawful_basis if {
	result := art5.result with input as {"normalized_data": {
		"privacy": {"lawful_basis_documented": false, "purpose_documented": true},
		"storage_resources": [],
		"dlp": {"policies_active": true},
		"policy_documents": [],
	}}
	result.compliant == false
	count(result.findings) > 0
}

test_no_encryption_on_storage if {
	result := art5.result with input as {"normalized_data": {
		"privacy": {"lawful_basis_documented": true, "purpose_documented": true},
		"storage_resources": [{"name": "bucket-pii", "encryption_enabled": false}],
		"dlp": {"policies_active": true},
		"policy_documents": [],
	}}
	result.compliant == false
}

test_stale_policy if {
	result := art5.result with input as {"normalized_data": {
		"privacy": {"lawful_basis_documented": true, "purpose_documented": true},
		"storage_resources": [],
		"dlp": {"policies_active": true},
		"policy_documents": [{"name": "Privacy Policy", "days_since_review": 400}],
	}}
	result.compliant == false
}
