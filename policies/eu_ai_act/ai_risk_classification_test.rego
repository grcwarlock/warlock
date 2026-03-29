package warlock.eu_ai_act_test

import rego.v1

import data.warlock.eu_ai_act

test_compliant_ai_systems if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [
			{
				"name": "fraud-detector",
				"risk_classification": "high",
				"risk_management_system": true,
				"transparency_disclosure": true,
				"human_oversight_mechanism": true,
				"interacts_with_humans": true,
				"uses_training_data": true,
				"data_governance_measures": true,
			},
			{
				"name": "chatbot-assistant",
				"risk_classification": "limited",
				"transparency_disclosure": true,
				"interacts_with_humans": true,
				"uses_training_data": false,
			},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unclassified_system if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [
			{
				"name": "unknown-model",
				"interacts_with_humans": false,
				"uses_training_data": false,
			},
		],
	}}
	result.compliant == false
	count(result.findings) > 0
}

test_high_risk_no_risk_management if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [
			{
				"name": "credit-scorer",
				"risk_classification": "high",
				"transparency_disclosure": true,
				"human_oversight_mechanism": true,
				"interacts_with_humans": true,
				"uses_training_data": false,
			},
		],
	}}
	result.compliant == false
}

test_no_transparency_disclosure if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [
			{
				"name": "virtual-agent",
				"risk_classification": "limited",
				"interacts_with_humans": true,
				"uses_training_data": false,
			},
		],
	}}
	result.compliant == false
}

test_high_risk_no_data_governance if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [
			{
				"name": "hiring-ranker",
				"risk_classification": "high",
				"risk_management_system": true,
				"transparency_disclosure": true,
				"human_oversight_mechanism": true,
				"interacts_with_humans": true,
				"uses_training_data": true,
			},
		],
	}}
	result.compliant == false
}

test_empty_systems_compliant if {
	result := eu_ai_act.result with input as {"normalized_data": {
		"ai_systems": [],
	}}
	result.compliant == true
}
