package warlock.eu_ai_act.art9_test

import rego.v1

import data.warlock.eu_ai_act.art9

test_compliant_risk_management if {
	result := art9.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "credit-scorer",
			"risk_classification": "high",
			"risk_management_system": true,
			"risks_identified": true,
			"misuse_risks_evaluated": true,
			"residual_risk_assessed": true,
			"risk_testing_performed": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_risk_management_system if {
	result := art9.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "hiring-ai",
			"risk_classification": "high",
		}],
	}}
	result.compliant == false
}

test_no_residual_risk_assessment if {
	result := art9.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-ai",
			"risk_classification": "high",
			"risk_management_system": true,
			"risks_identified": true,
			"misuse_risks_evaluated": true,
			"risk_testing_performed": true,
		}],
	}}
	result.compliant == false
}

test_low_risk_systems_pass if {
	result := art9.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "spam-filter",
			"risk_classification": "minimal",
		}],
	}}
	result.compliant == true
}
