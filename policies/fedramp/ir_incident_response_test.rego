package warlock.fedramp.ir_test

import rego.v1

import data.warlock.fedramp.ir

test_compliant_incident_response if {
	result := ir.result with input as {"normalized_data": {
		"incident_response": {
			"training_conducted": true,
			"automated_handling": true,
			"incident_tracking_enabled": true,
			"uscert_reporting_configured": true,
			"plan_documented": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_ir_plan if {
	result := ir.result with input as {"normalized_data": {
		"incident_response": {
			"training_conducted": true,
			"automated_handling": true,
			"incident_tracking_enabled": true,
			"uscert_reporting_configured": true,
			"plan_documented": false,
		},
	}}
	result.compliant == false
}

test_no_uscert_reporting if {
	result := ir.result with input as {"normalized_data": {
		"incident_response": {
			"training_conducted": true,
			"automated_handling": true,
			"incident_tracking_enabled": true,
			"uscert_reporting_configured": false,
			"plan_documented": true,
		},
	}}
	result.compliant == false
}

test_no_automated_handling if {
	result := ir.result with input as {"normalized_data": {
		"incident_response": {
			"training_conducted": true,
			"automated_handling": false,
			"incident_tracking_enabled": true,
			"uscert_reporting_configured": true,
			"plan_documented": true,
		},
	}}
	result.compliant == false
}
