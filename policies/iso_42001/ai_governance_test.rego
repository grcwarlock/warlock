package warlock.iso_42001_test

import rego.v1

import data.warlock.iso_42001

test_compliant_ai_governance if {
	result := iso_42001.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_policy_documented": true,
			"risk_assessment_conducted": true,
			"ai_systems": [{
				"name": "ml-pipeline",
				"impact_assessment_completed": true,
				"uses_training_data": true,
				"data_quality_controls": true,
				"risk_level": "high",
				"explainability_mechanism": true,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_ai_policy if {
	result := iso_42001.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_policy_documented": false,
			"risk_assessment_conducted": true,
			"ai_systems": [],
		},
	}}
	result.compliant == false
}

test_no_data_quality_controls if {
	result := iso_42001.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_policy_documented": true,
			"risk_assessment_conducted": true,
			"ai_systems": [{
				"name": "recommender",
				"impact_assessment_completed": true,
				"uses_training_data": true,
				"risk_level": "medium",
			}],
		},
	}}
	result.compliant == false
}

test_no_explainability_high_risk if {
	result := iso_42001.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_policy_documented": true,
			"risk_assessment_conducted": true,
			"ai_systems": [{
				"name": "credit-model",
				"impact_assessment_completed": true,
				"uses_training_data": false,
				"risk_level": "high",
			}],
		},
	}}
	result.compliant == false
}
