package iso_27001.a8.a8_22_test

import rego.v1

import data.iso_27001.a8.a8_22

test_compliant_a8_22 if {
	result := a8_22.result with input as {"normalized_data": {
		"vpcs": [],
		"vpc_peering": {
			"connections": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_22 if {
	result := a8_22.result with input as {"normalized_data": {
		"vpcs": [{"id": "vpc-123", "has_private_subnets": false, "tags": {}}],
		"vpc_peering": {"connections": []},
	}}
	result.compliant == false
}
