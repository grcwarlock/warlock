package nist.ps.ps_1_test

import rego.v1

import data.nist.ps.ps_1

test_compliant if {
	result := ps_1.result with input as {"normalized_data": {"personnel_security_policy": {"approved": true, "last_review_days": 100, "procedures_documented": true, "procedures_last_review_days": 100, "disseminated_to_personnel": true}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_1.result with input as {"normalized_data": {}}
	result.compliant == false
}
