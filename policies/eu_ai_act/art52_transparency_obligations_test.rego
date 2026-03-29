package warlock.eu_ai_act.art52_test

import rego.v1

import data.warlock.eu_ai_act.art52

test_compliant_transparency_obligations if {
	result := art52.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "chatbot",
			"interacts_with_humans": true,
			"transparency_disclosure": true,
			"uses_biometric_data": false,
			"generates_synthetic_content": false,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_ai_disclosure if {
	result := art52.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "virtual-assistant",
			"interacts_with_humans": true,
			"uses_biometric_data": false,
			"generates_synthetic_content": false,
		}],
	}}
	result.compliant == false
}

test_deepfake_not_labeled if {
	result := art52.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "image-generator",
			"interacts_with_humans": false,
			"uses_biometric_data": false,
			"generates_synthetic_content": true,
		}],
	}}
	result.compliant == false
}

test_biometric_no_disclosure if {
	result := art52.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "face-recognition",
			"interacts_with_humans": false,
			"uses_biometric_data": true,
			"generates_synthetic_content": false,
		}],
	}}
	result.compliant == false
}

test_no_interaction_passes if {
	result := art52.result with input as {"normalized_data": {
		"ai_systems": [{
			"name": "backend-ml",
			"interacts_with_humans": false,
			"uses_biometric_data": false,
			"generates_synthetic_content": false,
		}],
	}}
	result.compliant == true
}
