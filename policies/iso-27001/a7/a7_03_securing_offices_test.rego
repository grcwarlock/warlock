package iso_27001.a7.a7_03_test

import rego.v1

import data.iso_27001.a7.a7_03

test_compliant_a7_03 if {
	result := a7_03.result with input as {"normalized_data": {
		"vpcs_have_restricted_zones": true,
		"policies": {
			"facility_security_plan_documented": true,
		},
		"vpcs": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_03 if {
	result := a7_03.result with input as {"normalized_data": {}}
	result.compliant == false
}
