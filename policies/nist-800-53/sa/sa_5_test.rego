package nist.sa.sa_5_test

import rego.v1

import data.nist.sa.sa_5

test_compliant_documentation if {
	result := sa_5.result with input as {"normalized_data": {"system_documentation": {
		"user_guide_available": true,
		"last_update_days": 100,
		"security_configuration_documented": true,
		"architecture_documented": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_docs if {
	result := sa_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
