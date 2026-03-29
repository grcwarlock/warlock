package warlock.eu_ai_act.art15_test

import rego.v1

import data.warlock.eu_ai_act.art15

test_compliant_accuracy_robustness if {
	result := art15.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "fraud-detector",
			"risk_classification": "high",
			"accuracy_metrics_documented": true,
			"robustness_tested": true,
			"adversarial_testing_performed": true,
			"failsafe_mechanism": true,
			"ai_specific_security_measures": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_adversarial_testing if {
	result := art15.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "biometric-system",
			"risk_classification": "high",
			"accuracy_metrics_documented": true,
			"robustness_tested": true,
			"failsafe_mechanism": true,
			"ai_specific_security_measures": true,
		}],
	}}
	result.compliant == false
}

test_no_failsafe if {
	result := art15.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-ai",
			"risk_classification": "high",
			"accuracy_metrics_documented": true,
			"robustness_tested": true,
			"adversarial_testing_performed": true,
			"ai_specific_security_measures": true,
		}],
	}}
	result.compliant == false
}

test_minimal_risk_passes if {
	result := art15.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "content-filter",
			"risk_classification": "minimal",
		}],
	}}
	result.compliant == true
}
