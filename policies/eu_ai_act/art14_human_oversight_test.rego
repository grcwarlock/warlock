package warlock.eu_ai_act.art14_test

import rego.v1

import data.warlock.eu_ai_act.art14

test_compliant_human_oversight if {
	result := art14.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "credit-scorer",
			"risk_classification": "high",
			"human_oversight_mechanism": true,
			"oversight_risk_awareness": true,
			"capabilities_documented": true,
			"human_override_enabled": true,
			"interrupt_mechanism": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_override_capability if {
	result := art14.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "autonomous-vehicle",
			"risk_classification": "high",
			"human_oversight_mechanism": true,
			"oversight_risk_awareness": true,
			"capabilities_documented": true,
			"interrupt_mechanism": true,
		}],
	}}
	result.compliant == false
}

test_no_interrupt_mechanism if {
	result := art14.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "medical-device",
			"risk_classification": "high",
			"human_oversight_mechanism": true,
			"oversight_risk_awareness": true,
			"capabilities_documented": true,
			"human_override_enabled": true,
		}],
	}}
	result.compliant == false
}

test_low_risk_passes if {
	result := art14.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "recommendation-engine",
			"risk_classification": "minimal",
		}],
	}}
	result.compliant == true
}
