package hipaa.s164_316.s164_316_b_1_test

import rego.v1

import data.hipaa.s164_316.s164_316_b_1

test_compliant_retention if {
	result := s164_316_b_1.result with input as {"normalized_data": {"policies": {
		"document_retention_policy": true,
		"retention_period_years": 7,
		"documentation_accessible_to_workforce": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_insufficient_retention_period if {
	result := s164_316_b_1.result with input as {"normalized_data": {"policies": {
		"document_retention_policy": true,
		"retention_period_years": 3,
		"documentation_accessible_to_workforce": true,
	}}}
	result.compliant == false
}
