package nist.ps.ps_9_test

import rego.v1

import data.nist.ps.ps_9

test_compliant if {
	result := ps_9.result with input as {"normalized_data": {"position_descriptions": {"last_review_days": 100}, "positions": [{"title": "SecOps Engineer", "has_security_responsibilities": true, "security_role_in_description": true, "accountability_defined": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_9.result with input as {"normalized_data": {"positions": [{"title": "Admin", "has_security_responsibilities": true, "security_role_in_description": false, "accountability_defined": false}]}}
	result.compliant == false
}
