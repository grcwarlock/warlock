package hipaa.s164_308.s164_308_a_8_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_8

test_compliant_evaluation if {
	result := s164_308_a_8.result with input as {"normalized_data": {"policies": {
		"security_evaluation_performed": true,
		"last_evaluation_days": 100,
		"evaluation_covers_all_controls": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_evaluation_performed if {
	result := s164_308_a_8.result with input as {"normalized_data": {"policies": {
		"security_evaluation_performed": false,
		"last_evaluation_days": 0,
		"evaluation_covers_all_controls": false,
	}}}
	result.compliant == false
}
