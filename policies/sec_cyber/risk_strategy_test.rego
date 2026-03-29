package warlock.sec_cyber.risk_strategy_test

import rego.v1

import data.warlock.sec_cyber.risk_strategy

test_compliant_risk_strategy if {
	result := risk_strategy.result with input as {"normalized_data": {
		"sec_cyber": {
			"risk_assessment_process_documented": true,
			"cyber_risk_integrated_with_erm": true,
			"external_assessment_conducted": true,
			"vendor_risk_oversight": true,
			"prior_incident_analysis": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_risk_process if {
	result := risk_strategy.result with input as {"normalized_data": {
		"sec_cyber": {
			"risk_assessment_process_documented": false,
			"cyber_risk_integrated_with_erm": true,
			"external_assessment_conducted": true,
			"vendor_risk_oversight": true,
			"prior_incident_analysis": true,
		},
	}}
	result.compliant == false
}

test_no_erm_integration if {
	result := risk_strategy.result with input as {"normalized_data": {
		"sec_cyber": {
			"risk_assessment_process_documented": true,
			"cyber_risk_integrated_with_erm": false,
			"external_assessment_conducted": true,
			"vendor_risk_oversight": true,
			"prior_incident_analysis": true,
		},
	}}
	result.compliant == false
}

test_no_vendor_oversight if {
	result := risk_strategy.result with input as {"normalized_data": {
		"sec_cyber": {
			"risk_assessment_process_documented": true,
			"cyber_risk_integrated_with_erm": true,
			"external_assessment_conducted": true,
			"vendor_risk_oversight": false,
			"prior_incident_analysis": true,
		},
	}}
	result.compliant == false
}
