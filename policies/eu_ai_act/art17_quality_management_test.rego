package warlock.eu_ai_act.art17_test

import rego.v1

import data.warlock.eu_ai_act.art17

test_compliant_qms if {
	result := art17.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "fraud-detector",
			"risk_classification": "high",
			"quality_management_system": true,
			"compliance_strategy_documented": true,
			"uses_training_data": true,
			"data_management_procedures": true,
			"post_market_monitoring": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_qms if {
	result := art17.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "credit-scorer",
			"risk_classification": "high",
		}],
	}}
	result.compliant == false
}

test_no_post_market_monitoring if {
	result := art17.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-ai",
			"risk_classification": "high",
			"quality_management_system": true,
			"compliance_strategy_documented": true,
			"uses_training_data": false,
		}],
	}}
	result.compliant == false
}

test_low_risk_passes if {
	result := art17.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "spell-checker",
			"risk_classification": "minimal",
		}],
	}}
	result.compliant == true
}
