package nist.ir.ir_7_test

import rego.v1

import data.nist.ir.ir_7

test_compliant_ir_assistance if {
	result := ir_7.result with input as {"normalized_data": {
		"ir_assistance": {
			"help_desk_available": true,
			"available_24x7": true,
			"knowledge_base_available": true,
			"contact_information_published": true,
			"response_sla_defined": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_assistance if {
	result := ir_7.result with input as {"normalized_data": {}}
	result.compliant == false
}
