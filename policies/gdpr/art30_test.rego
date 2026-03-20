package gdpr.art30_test

import rego.v1

import data.gdpr.art30

test_compliant_ropa if {
	result := art30.result with input as {"normalized_data": {
		"privacy": {"ropa_maintained": true, "ropa_days_since_update": 60},
		"processing_activities": [{"name": "payroll", "recorded_in_ropa": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_ropa if {
	result := art30.result with input as {"normalized_data": {
		"privacy": {"ropa_maintained": false},
		"processing_activities": [],
	}}
	result.compliant == false
}

test_stale_ropa if {
	result := art30.result with input as {"normalized_data": {
		"privacy": {"ropa_maintained": true, "ropa_days_since_update": 400},
		"processing_activities": [],
	}}
	result.compliant == false
}

test_unrecorded_activity if {
	result := art30.result with input as {"normalized_data": {
		"privacy": {"ropa_maintained": true, "ropa_days_since_update": 30},
		"processing_activities": [{"name": "marketing", "recorded_in_ropa": false}],
	}}
	result.compliant == false
}
