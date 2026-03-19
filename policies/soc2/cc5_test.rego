package soc2.cc5_test

import rego.v1

import data.soc2.cc5

test_compliant_control_activities if {
	result := cc5.result with input as {"normalized_data": {"governance": {
		"control_inventory_exists": true,
		"automated_control_percentage": 75,
		"technology_general_controls_defined": true,
		"segregation_of_duties_enforced": true,
		"policies_distributed": true,
		"policies": [{"name": "P1", "review_age_days": 100}],
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_inventory if {
	result := cc5.result with input as {"normalized_data": {"governance": {
		"policies": [],
	}}}
	result.compliant == false
}
