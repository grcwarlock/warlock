package warlock.iso_42001.data_mgmt_test

import rego.v1

import data.warlock.iso_42001.data_mgmt

test_compliant_data_management if {
	result := data_mgmt.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_inventory_maintained": true,
			"ai_systems": [{
				"name": "ml-pipeline",
				"uses_training_data": true,
				"data_quality_requirements_defined": true,
				"data_provenance_tracked": true,
				"data_preparation_documented": true,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_inventory if {
	result := data_mgmt.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_inventory_maintained": false,
			"ai_systems": [],
		},
	}}
	result.compliant == false
}

test_no_data_provenance if {
	result := data_mgmt.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_inventory_maintained": true,
			"ai_systems": [{
				"name": "classifier",
				"uses_training_data": true,
				"data_quality_requirements_defined": true,
				"data_preparation_documented": true,
			}],
		},
	}}
	result.compliant == false
}

test_no_training_data_passes if {
	result := data_mgmt.result with input as {"normalized_data": {
		"ai_governance": {
			"ai_inventory_maintained": true,
			"ai_systems": [{
				"name": "rule-engine",
				"uses_training_data": false,
			}],
		},
	}}
	result.compliant == true
}
