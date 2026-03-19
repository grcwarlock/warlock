package nist.ps.ps_3_test

import rego.v1

import data.nist.ps.ps_3

test_compliant if {
	result := ps_3.result with input as {"normalized_data": {"personnel_screening": {"rescreening_interval_days": 1825}, "personnel": [{"name": "Alice", "requires_screening": true, "screening_completed": true, "screening_expiration_days": 365, "days_since_last_screening": 100, "screening_commensurate_with_risk": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_3.result with input as {"normalized_data": {"personnel": [{"name": "Bob", "requires_screening": true, "screening_completed": false}]}}
	result.compliant == false
}
