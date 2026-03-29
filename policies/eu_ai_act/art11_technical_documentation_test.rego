package warlock.eu_ai_act.art11_test

import rego.v1

import data.warlock.eu_ai_act.art11

test_compliant_documentation if {
	result := art11.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "credit-scorer",
			"risk_classification": "high",
			"technical_documentation": true,
			"general_description_documented": true,
			"intended_purpose_documented": true,
			"performance_metrics_documented": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_technical_documentation if {
	result := art11.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "hiring-ai",
			"risk_classification": "high",
		}],
	}}
	result.compliant == false
}

test_missing_performance_metrics if {
	result := art11.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-ai",
			"risk_classification": "high",
			"technical_documentation": true,
			"general_description_documented": true,
			"intended_purpose_documented": true,
		}],
	}}
	result.compliant == false
}

test_low_risk_no_docs_required if {
	result := art11.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "autocomplete",
			"risk_classification": "minimal",
		}],
	}}
	result.compliant == true
}
