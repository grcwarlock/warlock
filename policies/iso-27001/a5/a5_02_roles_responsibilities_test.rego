package iso_27001.a5.a5_02_test

import rego.v1

import data.iso_27001.a5.a5_02

test_compliant_a5_02 if {
	result := a5_02.result with input as {"normalized_data": {
		"iam": {
			"security_roles_defined": true,
			"roles": [{"name": "SecurityAdmin", "attached_policies": ["AdminPolicy"]}],
		},
		"account": {
			"security_contact_configured": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_02 if {
	result := a5_02.result with input as {"normalized_data": {}}
	result.compliant == false
}
