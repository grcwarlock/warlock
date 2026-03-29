package warlock.sec_cyber.materiality_test

import rego.v1

import data.warlock.sec_cyber.materiality

test_compliant_materiality if {
	result := materiality.result with input as {"normalized_data": {
		"sec_cyber": {
			"materiality_assessment_process": true,
			"materiality_criteria_defined": true,
			"incident_aggregation_analysis": true,
			"incidents": [{
				"id": "INC-001",
				"materiality_assessed": true,
				"is_material": false,
				"business_days_since_discovery": 2,
			}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_late_materiality_assessment if {
	result := materiality.result with input as {"normalized_data": {
		"sec_cyber": {
			"materiality_assessment_process": true,
			"materiality_criteria_defined": true,
			"incident_aggregation_analysis": true,
			"incidents": [{
				"id": "INC-002",
				"materiality_assessed": false,
				"business_days_since_discovery": 7,
			}],
		},
	}}
	result.compliant == false
}

test_undisclosed_material_incident if {
	result := materiality.result with input as {"normalized_data": {
		"sec_cyber": {
			"materiality_assessment_process": true,
			"materiality_criteria_defined": true,
			"incident_aggregation_analysis": true,
			"incidents": [{
				"id": "INC-003",
				"materiality_assessed": true,
				"is_material": true,
				"sec_disclosed": false,
				"business_days_since_discovery": 3,
			}],
		},
	}}
	result.compliant == false
}

test_no_materiality_process if {
	result := materiality.result with input as {"normalized_data": {
		"sec_cyber": {
			"materiality_assessment_process": false,
			"materiality_criteria_defined": true,
			"incident_aggregation_analysis": true,
			"incidents": [],
		},
	}}
	result.compliant == false
}
