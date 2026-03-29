package warlock.iso_27701_test

import rego.v1

import data.warlock.iso_27701

test_compliant_privacy_controls if {
	result := iso_27701.result with input as {"normalized_data": {
		"privacy": {
			"purpose_limitation_policy": true,
			"data_subject_rights_enabled": true,
			"privacy_impact_assessment_conducted": true,
			"data_collections": [
				{"name": "signup-form", "fields_collected": 3, "fields_required": 3},
			],
			"cross_border_transfers": [
				{"destination": "EU", "safeguards_in_place": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_excessive_data_collection if {
	result := iso_27701.result with input as {"normalized_data": {
		"privacy": {
			"purpose_limitation_policy": true,
			"data_subject_rights_enabled": true,
			"privacy_impact_assessment_conducted": true,
			"data_collections": [
				{"name": "registration", "fields_collected": 20, "fields_required": 5},
			],
			"cross_border_transfers": [],
		},
	}}
	result.compliant == false
}

test_no_data_subject_rights if {
	result := iso_27701.result with input as {"normalized_data": {
		"privacy": {
			"purpose_limitation_policy": true,
			"data_subject_rights_enabled": false,
			"privacy_impact_assessment_conducted": true,
			"data_collections": [],
			"cross_border_transfers": [],
		},
	}}
	result.compliant == false
}

test_unsafe_cross_border_transfer if {
	result := iso_27701.result with input as {"normalized_data": {
		"privacy": {
			"purpose_limitation_policy": true,
			"data_subject_rights_enabled": true,
			"privacy_impact_assessment_conducted": true,
			"data_collections": [],
			"cross_border_transfers": [
				{"destination": "Third Country", "safeguards_in_place": false},
			],
		},
	}}
	result.compliant == false
}
