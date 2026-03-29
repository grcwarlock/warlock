package warlock.fedramp.ac_test

import rego.v1

import data.warlock.fedramp.ac

test_compliant_access_control if {
	result := ac.result with input as {"normalized_data": {
		"users": [{
			"username": "alice",
			"provisioning_approved": true,
			"is_active": true,
			"days_since_last_login": 5,
			"policies": [{"name": "ReadOnly", "effect": "Allow", "action": "s3:Get*", "resource": "arn:aws:s3:::*"}],
		}],
		"remote_access": {"connections": [{"id": "vpn-1", "encrypted": true}]},
		"public_resources": [{"id": "website", "authorized": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_inactive_account if {
	result := ac.result with input as {"normalized_data": {
		"users": [{
			"username": "stale-user",
			"provisioning_approved": true,
			"is_active": true,
			"days_since_last_login": 120,
			"policies": [],
		}],
		"remote_access": {"connections": []},
		"public_resources": [],
	}}
	result.compliant == false
}

test_excessive_privilege if {
	result := ac.result with input as {"normalized_data": {
		"users": [{
			"username": "admin",
			"provisioning_approved": true,
			"is_active": true,
			"days_since_last_login": 1,
			"policies": [{"name": "AdminAccess", "effect": "Allow", "action": "*", "resource": "*"}],
		}],
		"remote_access": {"connections": []},
		"public_resources": [],
	}}
	result.compliant == false
}

test_unencrypted_remote_access if {
	result := ac.result with input as {"normalized_data": {
		"users": [],
		"remote_access": {"connections": [{"id": "rdp-1", "encrypted": false}]},
		"public_resources": [],
	}}
	result.compliant == false
}
