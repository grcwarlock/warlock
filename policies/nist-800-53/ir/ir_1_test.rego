package nist.ir.ir_1_test

import rego.v1

import data.nist.ir.ir_1

test_compliant_ir_policy if {
	result := ir_1.result with input as {"normalized_data": {
		"ir_policy": {
			"exists": true,
			"last_review_days": 100,
			"designated_official": "Jane Doe",
			"scope_defined": true,
			"disseminated": true,
			"procedures_documented": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ir_policy if {
	result := ir_1.result with input as {"normalized_data": {}}
	result.compliant == false
}
