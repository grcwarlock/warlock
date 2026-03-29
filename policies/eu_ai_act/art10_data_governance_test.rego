package warlock.eu_ai_act.art10_test

import rego.v1

import data.warlock.eu_ai_act.art10

test_compliant_data_governance if {
	result := art10.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "fraud-detector",
			"risk_classification": "high",
			"uses_training_data": true,
			"data_governance_measures": true,
			"data_collection_documented": true,
			"bias_examination_performed": true,
			"data_representativeness_verified": true,
			"validation_dataset_defined": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_bias_examination if {
	result := art10.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "hiring-ranker",
			"risk_classification": "high",
			"uses_training_data": true,
			"data_governance_measures": true,
			"data_collection_documented": true,
			"data_representativeness_verified": true,
			"validation_dataset_defined": true,
		}],
	}}
	result.compliant == false
}

test_no_training_data_passes if {
	result := art10.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "rule-engine",
			"risk_classification": "high",
			"uses_training_data": false,
		}],
	}}
	result.compliant == true
}

test_low_risk_with_training_data_passes if {
	result := art10.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "spam-filter",
			"risk_classification": "minimal",
			"uses_training_data": true,
		}],
	}}
	result.compliant == true
}
