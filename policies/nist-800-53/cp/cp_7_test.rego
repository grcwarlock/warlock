package nist.cp.cp_7_test

import rego.v1

import data.nist.cp.cp_7

test_compliant_alternate_processing if {
	result := cp_7.result with input as {
		"provider": "aws",
		"normalized_data": {
			"alternate_processing": {
				"multi_region_enabled": true,
				"failover_configured": true,
				"estimated_rto_hours": 4,
				"required_rto_hours": 8,
				"transfer_agreement_documented": true,
				"last_failover_test_days": 180,
			},
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_alternate_processing if {
	result := cp_7.result with input as {
		"provider": "aws",
		"normalized_data": {},
	}
	result.compliant == false
}
