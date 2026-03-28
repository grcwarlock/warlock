package soc2.cc6_test

import rego.v1

import data.soc2.cc6

test_compliant_logical_access if {
	result := cc6.result with input as {"normalized_data": {
		"users": [{"username": "user1", "mfa_enabled": true, "provisioning_approved": true, "created_within_days": 5, "days_since_last_login": 1, "is_active": true, "policies": [{"name": "ReadOnly", "effect": "Allow", "action": "s3:Get*", "resource": "arn:aws:s3:::*"}]}],
		"root_account": {"access_keys_present": false},
		"security_groups": [],
		"network_security": {"ids_enabled": true, "ips_enabled": true},
		"endpoints": [],
		"endpoint_protection": {"application_whitelisting": true, "edr_enabled": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_mfa if {
	result := cc6.result with input as {"normalized_data": {
		"users": [{"username": "user1", "mfa_enabled": false, "policies": []}],
		"root_account": {"access_keys_present": false},
		"security_groups": [],
		"network_security": {"ids_enabled": true, "ips_enabled": true},
		"endpoints": [],
		"endpoint_protection": {"application_whitelisting": true, "edr_enabled": true},
	}}
	result.compliant == false
}
