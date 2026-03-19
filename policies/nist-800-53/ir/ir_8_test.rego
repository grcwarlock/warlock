package nist.ir.ir_8_test

import rego.v1

import data.nist.ir.ir_8

test_compliant_ir_plan if {
	result := ir_8.result with input as {"normalized_data": {
		"ir_plan": {
			"last_review_days": 180,
			"organizational_structure_defined": true,
			"roles_responsibilities_defined": true,
			"incident_categories_defined": true,
			"metrics_defined": true,
			"distributed_to_personnel": true,
			"aligned_with_contingency_plan": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ir_plan if {
	result := ir_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
