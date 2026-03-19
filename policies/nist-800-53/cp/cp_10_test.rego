package nist.cp.cp_10_test

import rego.v1

import data.nist.cp.cp_10

test_compliant_recovery if {
	result := cp_10.result with input as {
		"provider": "aws",
		"normalized_data": {
			"recovery_procedures": {
				"runbooks_exist": true,
				"last_recovery_test_days": 180,
				"known_state_baseline": true,
				"transaction_based_system": false,
				"infrastructure_as_code": true,
			},
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_recovery if {
	result := cp_10.result with input as {
		"provider": "aws",
		"normalized_data": {},
	}
	result.compliant == false
}
