package warlock.iso_27701.dsr_test

import rego.v1

import data.warlock.iso_27701.dsr

test_compliant_dsr if {
	result := dsr.result with input as {"normalized_data": {
		"privacy": {
			"dsr_access_process": true,
			"dsr_rectification_process": true,
			"dsr_erasure_process": true,
			"dsr_portability_supported": true,
			"dsr_requests": [
				{"id": "DSR-001", "completed": true, "days_since_receipt": 15},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_erasure_process if {
	result := dsr.result with input as {"normalized_data": {
		"privacy": {
			"dsr_access_process": true,
			"dsr_rectification_process": true,
			"dsr_erasure_process": false,
			"dsr_portability_supported": true,
			"dsr_requests": [],
		},
	}}
	result.compliant == false
}

test_overdue_request if {
	result := dsr.result with input as {"normalized_data": {
		"privacy": {
			"dsr_access_process": true,
			"dsr_rectification_process": true,
			"dsr_erasure_process": true,
			"dsr_portability_supported": true,
			"dsr_requests": [
				{"id": "DSR-002", "completed": false, "days_since_receipt": 45},
			],
		},
	}}
	result.compliant == false
}

test_completed_request_passes if {
	result := dsr.result with input as {"normalized_data": {
		"privacy": {
			"dsr_access_process": true,
			"dsr_rectification_process": true,
			"dsr_erasure_process": true,
			"dsr_portability_supported": true,
			"dsr_requests": [
				{"id": "DSR-003", "completed": true, "days_since_receipt": 60},
			],
		},
	}}
	result.compliant == true
}
