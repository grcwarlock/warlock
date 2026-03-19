package nist.cp.cp_2_test

import rego.v1

import data.nist.cp.cp_2

test_compliant_contingency_plan if {
	result := cp_2.result with input as {"normalized_data": {
		"contingency_plan": {
			"last_review_days": 180,
			"essential_missions_identified": true,
			"recovery_objectives_defined": true,
			"roles_assigned": true,
			"contact_list_current": true,
			"distributed_to_personnel": true,
			"system_inventory_included": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_plan if {
	result := cp_2.result with input as {"normalized_data": {}}
	result.compliant == false
}
