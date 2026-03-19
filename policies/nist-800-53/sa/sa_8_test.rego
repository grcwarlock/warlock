package nist.sa.sa_8_test

import rego.v1

import data.nist.sa.sa_8

test_compliant_engineering if {
	result := sa_8.result with input as {"normalized_data": {"security_engineering": {
		"defense_in_depth": true,
		"least_privilege_design": true,
		"secure_defaults": true,
		"fail_secure": true,
		"principles_documented": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_engineering if {
	result := sa_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
