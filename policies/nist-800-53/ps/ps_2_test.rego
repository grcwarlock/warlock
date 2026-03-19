package nist.ps.ps_2_test

import rego.v1

import data.nist.ps.ps_2

test_compliant if {
	result := ps_2.result with input as {"normalized_data": {"position_risk_designations": {"last_review_days": 100}, "positions": [{"title": "SysAdmin", "risk_designation": "high", "screening_criteria_established": true, "consistent_with_opm_policy": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_2.result with input as {"normalized_data": {"positions": [{"title": "SysAdmin"}]}}
	result.compliant == false
}
