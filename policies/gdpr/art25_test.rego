package gdpr.art25_test

import rego.v1

import data.gdpr.art25

test_compliant_data_protection_by_design if {
	result := art25.result with input as {"normalized_data": {
		"storage_resources": [{"name": "db-prod", "encryption_enabled": true, "public_access": false}],
		"processing_activities": [{"name": "payroll", "high_risk": true, "dpia_completed": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_public_storage if {
	result := art25.result with input as {"normalized_data": {
		"storage_resources": [{"name": "bucket-pii", "encryption_enabled": true, "public_access": true}],
		"processing_activities": [],
	}}
	result.compliant == false
}

test_missing_dpia if {
	result := art25.result with input as {"normalized_data": {
		"storage_resources": [],
		"processing_activities": [{"name": "profiling", "high_risk": true, "dpia_completed": false}],
	}}
	result.compliant == false
}
