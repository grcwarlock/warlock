package warlock.iso_42001.lifecycle_test

import rego.v1

import data.warlock.iso_42001.lifecycle

test_compliant_lifecycle if {
	result := lifecycle.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_systems": [{
				"name": "fraud-detector",
				"development_process_documented": true,
				"validation_performed": true,
				"in_production": true,
				"controlled_deployment": true,
				"deprecated": false,
				"performance_monitoring_enabled": true,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_validation if {
	result := lifecycle.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_systems": [{
				"name": "recommender",
				"development_process_documented": true,
				"in_production": false,
				"deprecated": false,
			}],
		},
	}}
	result.compliant == false
}

test_uncontrolled_production_deployment if {
	result := lifecycle.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_systems": [{
				"name": "chatbot",
				"development_process_documented": true,
				"validation_performed": true,
				"in_production": true,
				"controlled_deployment": false,
				"deprecated": false,
				"performance_monitoring_enabled": true,
			}],
		},
	}}
	result.compliant == false
}

test_deprecated_no_retirement if {
	result := lifecycle.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_systems": [{
				"name": "legacy-model",
				"development_process_documented": true,
				"validation_performed": true,
				"in_production": false,
				"deprecated": true,
			}],
		},
	}}
	result.compliant == false
}
