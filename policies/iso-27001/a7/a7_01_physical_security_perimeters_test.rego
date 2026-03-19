package iso_27001.a7.a7_01_test

import rego.v1

import data.iso_27001.a7.a7_01

test_compliant_a7_01 if {
	result := a7_01.result with input as {"normalized_data": {
		"organization": {
			"region_restriction_scps_exist": true,
			"region_scp_attached_to_all_ous": true,
		},
		"policies": {
			"physical_security_perimeter_documented": true,
		},
		"resources": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_01 if {
	result := a7_01.result with input as {"normalized_data": {}}
	result.compliant == false
}
