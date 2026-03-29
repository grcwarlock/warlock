package warlock.iso_27701.pia_test

import rego.v1

import data.warlock.iso_27701.pia

test_compliant_pia if {
	result := pia.result with input as {"normalized_data": {
		"privacy": {
			"pia_management_review": true,
			"processing_activities": [{
				"name": "ai-profiling",
				"high_risk": true,
				"pia_conducted": true,
				"processing_changed_since_pia": false,
				"pia_risks_mitigated": true,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_pia_for_high_risk if {
	result := pia.result with input as {"normalized_data": {
		"privacy": {
			"pia_management_review": true,
			"processing_activities": [{
				"name": "biometric-auth",
				"high_risk": true,
				"pia_conducted": false,
			}],
		},
	}}
	result.compliant == false
}

test_stale_pia if {
	result := pia.result with input as {"normalized_data": {
		"privacy": {
			"pia_management_review": true,
			"processing_activities": [{
				"name": "marketing",
				"high_risk": false,
				"pia_conducted": true,
				"processing_changed_since_pia": true,
				"pia_reviewed": false,
				"pia_risks_mitigated": true,
			}],
		},
	}}
	result.compliant == false
}

test_low_risk_no_pia_ok if {
	result := pia.result with input as {"normalized_data": {
		"privacy": {
			"pia_management_review": true,
			"processing_activities": [{
				"name": "logging",
				"high_risk": false,
			}],
		},
	}}
	result.compliant == true
}
