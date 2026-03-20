package gdpr.art35_test

import rego.v1

import data.gdpr.art35

test_compliant_dpia if {
	result := art35.result with input as {"normalized_data": {
		"processing_activities": [{"name": "profiling", "high_risk": true, "dpia_completed": true, "dpia_days_since_review": 90}],
		"policies": {"dpia_policy_documented": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_missing_dpia if {
	result := art35.result with input as {"normalized_data": {
		"processing_activities": [{"name": "automated-decisions", "high_risk": true, "dpia_completed": false}],
		"policies": {"dpia_policy_documented": true},
	}}
	result.compliant == false
}

test_stale_dpia if {
	result := art35.result with input as {"normalized_data": {
		"processing_activities": [{"name": "scoring", "high_risk": true, "dpia_completed": true, "dpia_days_since_review": 400}],
		"policies": {"dpia_policy_documented": true},
	}}
	result.compliant == false
}

test_no_dpia_policy if {
	result := art35.result with input as {"normalized_data": {
		"processing_activities": [],
		"policies": {"dpia_policy_documented": false},
	}}
	result.compliant == false
}

test_low_risk_no_dpia_ok if {
	result := art35.result with input as {"normalized_data": {
		"processing_activities": [{"name": "newsletter", "high_risk": false}],
		"policies": {"dpia_policy_documented": true},
	}}
	result.compliant == true
}
