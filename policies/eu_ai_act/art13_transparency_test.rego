package warlock.eu_ai_act.art13_test

import rego.v1

import data.warlock.eu_ai_act.art13

test_compliant_transparency if {
	result := art13.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "fraud-detector",
			"risk_classification": "high",
			"output_interpretable": true,
			"usage_instructions_provided": true,
			"intended_purpose_documented": true,
			"accuracy_metrics_disclosed": true,
			"lifecycle_documented": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_interpretability if {
	result := art13.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "black-box-model",
			"risk_classification": "high",
			"usage_instructions_provided": true,
			"intended_purpose_documented": true,
			"accuracy_metrics_disclosed": true,
			"lifecycle_documented": true,
		}],
	}}
	result.compliant == false
}

test_no_accuracy_disclosure if {
	result := art13.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-ai",
			"risk_classification": "high",
			"output_interpretable": true,
			"usage_instructions_provided": true,
			"intended_purpose_documented": true,
			"lifecycle_documented": true,
		}],
	}}
	result.compliant == false
}

test_limited_risk_passes if {
	result := art13.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "chatbot",
			"risk_classification": "limited",
		}],
	}}
	result.compliant == true
}
