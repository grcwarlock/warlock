package nist.sa.sa_17_test

import rego.v1

import data.nist.sa.sa_17

test_compliant_security_arch if {
	result := sa_17.result with input as {"normalized_data": {"developer_security_architecture": {
		"consistent_with_enterprise_architecture": true,
		"threat_model_completed": true,
		"last_review_days": 100,
		"security_mechanisms_documented": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_arch if {
	result := sa_17.result with input as {"normalized_data": {}}
	result.compliant == false
}
