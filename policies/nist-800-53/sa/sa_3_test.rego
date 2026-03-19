package nist.sa.sa_3_test

import rego.v1

import data.nist.sa.sa_3

test_compliant_sdlc if {
	result := sa_3.result with input as {"normalized_data": {"sdlc": {
		"security_integrated": true,
		"privacy_integrated": true,
		"security_roles_defined": true,
		"last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_sdlc if {
	result := sa_3.result with input as {"normalized_data": {}}
	result.compliant == false
}
