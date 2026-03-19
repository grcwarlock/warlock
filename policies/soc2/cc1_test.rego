package soc2.cc1_test

import rego.v1

import data.soc2.cc1

test_compliant_control_environment if {
	result := cc1.result with input as {"normalized_data": {"governance": {
		"code_of_conduct_exists": true,
		"employees": [{"name": "emp1", "ethics_training_current": true}],
		"audit_committee_charter_exists": true,
		"board_meetings_per_year": 6,
		"org_chart_documented": true,
		"roles_and_responsibilities_defined": true,
		"competency_requirements_defined": true,
		"accountability_policy_exists": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_code_of_conduct if {
	result := cc1.result with input as {"normalized_data": {"governance": {
		"employees": [],
		"board_meetings_per_year": 6,
		"org_chart_documented": true,
		"roles_and_responsibilities_defined": true,
		"competency_requirements_defined": true,
		"accountability_policy_exists": true,
		"audit_committee_charter_exists": true,
	}}}
	result.compliant == false
}
