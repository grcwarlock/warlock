package nist.sr.sr_3_test

import rego.v1

import data.nist.sr.sr_3

test_compliant_controls if {
	result := sr_3.result with input as {"normalized_data": {"supply_chain_controls": {
		"provenance_tracking": true,
		"supplier_diversity_considered": true,
		"counterfeit_prevention": true,
		"last_assessment_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_controls if {
	result := sr_3.result with input as {"normalized_data": {}}
	result.compliant == false
}
