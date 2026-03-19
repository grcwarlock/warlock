package hipaa.s164_314.s164_314_a_1_test

import rego.v1

import data.hipaa.s164_314.s164_314_a_1

test_compliant_business_associates if {
	result := s164_314_a_1.result with input as {"normalized_data": {
		"policies": {
			"business_associate_policy": true,
			"business_associate_inventory_maintained": true,
		},
		"resources": {"business_associates": [
			{"name": "CloudCorp", "baa_signed": true, "baa_expired": false},
		]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_missing_baa if {
	result := s164_314_a_1.result with input as {"normalized_data": {
		"policies": {
			"business_associate_policy": true,
			"business_associate_inventory_maintained": true,
		},
		"resources": {"business_associates": [
			{"name": "CloudCorp", "baa_signed": false, "baa_expired": false},
		]},
	}}
	result.compliant == false
}
