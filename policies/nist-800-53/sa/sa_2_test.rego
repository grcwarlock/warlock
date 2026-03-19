package nist.sa.sa_2_test

import rego.v1

import data.nist.sa.sa_2

test_compliant_allocation if {
	result := sa_2.result with input as {"normalized_data": {"security_resource_allocation": {
		"budget_allocated": true,
		"staffing_allocated": true,
		"documented_in_programming": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_allocation if {
	result := sa_2.result with input as {"normalized_data": {}}
	result.compliant == false
}
