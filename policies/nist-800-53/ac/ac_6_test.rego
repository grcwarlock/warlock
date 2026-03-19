package nist.ac.ac_6_test

import rego.v1

import data.nist.ac.ac_6

test_compliant_least_privilege if {
	result := ac_6.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "policies": [{"effect": "Allow", "action": "s3:GetObject", "resource": "arn:aws:s3:::bucket/*", "name": "ReadOnly", "is_aws_managed": false}], "access_keys": []},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_wildcard_admin if {
	result := ac_6.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "policies": [{"effect": "Allow", "action": "*", "resource": "*", "name": "AdminAccess", "is_aws_managed": false}], "access_keys": []},
		],
	}}
	result.compliant == false
}
