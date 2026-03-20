package gdpr.art17_test

import rego.v1

import data.gdpr.art17

test_compliant_erasure if {
	result := art17.result with input as {"normalized_data": {
		"policies": {"erasure_process_documented": true},
		"dsar_requests": [{"id": "DSAR-001", "type": "erasure", "status": "completed", "days_open": 5}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_erasure_process if {
	result := art17.result with input as {"normalized_data": {
		"policies": {"erasure_process_documented": false},
		"dsar_requests": [],
	}}
	result.compliant == false
}

test_overdue_erasure_request if {
	result := art17.result with input as {"normalized_data": {
		"policies": {"erasure_process_documented": true},
		"dsar_requests": [{"id": "DSAR-002", "type": "erasure", "status": "pending", "days_open": 45}],
	}}
	result.compliant == false
}

test_non_erasure_request_ignored if {
	result := art17.result with input as {"normalized_data": {
		"policies": {"erasure_process_documented": true},
		"dsar_requests": [{"id": "DSAR-003", "type": "access", "status": "pending", "days_open": 60}],
	}}
	result.compliant == true
}
