package nist.ps.ps_8_test

import rego.v1

import data.nist.ps.ps_8

test_compliant if {
	result := ps_8.result with input as {"normalized_data": {"personnel_sanctions": {"sanctions_documented": true, "due_process_defined": true, "communicated_to_personnel": true, "escalation_procedures": true}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
