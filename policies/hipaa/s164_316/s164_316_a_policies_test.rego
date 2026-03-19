package hipaa.s164_316.s164_316_a_test

import rego.v1

import data.hipaa.s164_316.s164_316_a

test_compliant_policies if {
	result := s164_316_a.result with input as {"normalized_data": {"policies": {
		"security_policies_documented": true,
		"policy_review_scheduled": true,
		"last_policy_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_security_policies if {
	result := s164_316_a.result with input as {"normalized_data": {"policies": {
		"security_policies_documented": false,
		"policy_review_scheduled": false,
		"last_policy_review_days": 0,
	}}}
	result.compliant == false
}
