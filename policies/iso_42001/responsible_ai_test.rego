package warlock.iso_42001.responsible_test

import rego.v1

import data.warlock.iso_42001.responsible

test_compliant_responsible_ai if {
	result := responsible.result with input as {"normalized_data": {
		"ai_governance": {
			"roles_defined": true,
			"ai_systems": [{
				"name": "credit-model",
				"objectives_aligned": true,
				"risk_level": "high",
				"fairness_assessment_conducted": true,
				"uses_third_party_components": true,
				"third_party_assessed": true,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_fairness_assessment if {
	result := responsible.result with input as {"normalized_data": {
		"ai_governance": {
			"roles_defined": true,
			"ai_systems": [{
				"name": "hiring-ai",
				"objectives_aligned": true,
				"risk_level": "high",
				"uses_third_party_components": false,
			}],
		},
	}}
	result.compliant == false
}

test_unassessed_third_party if {
	result := responsible.result with input as {"normalized_data": {
		"ai_governance": {
			"roles_defined": true,
			"ai_systems": [{
				"name": "nlp-model",
				"objectives_aligned": true,
				"risk_level": "medium",
				"uses_third_party_components": true,
				"third_party_assessed": false,
			}],
		},
	}}
	result.compliant == false
}

test_no_roles_defined if {
	result := responsible.result with input as {"normalized_data": {
		"ai_governance": {
			"roles_defined": false,
			"ai_systems": [],
		},
	}}
	result.compliant == false
}
