package pci_dss.r8_test

import rego.v1

import data.pci_dss.r8

test_compliant_auth if {
	result := r8.result with input as {"normalized_data": {
		"users": [{"username": "user1", "mfa_enabled": true}],
		"password_policy": {"min_length": 14},
		"service_accounts": [{"name": "svc-app", "shared": false, "managed": true}],
	}}
	result.compliant == true
}

test_noncompliant_no_mfa if {
	result := r8.result with input as {"normalized_data": {
		"users": [{"username": "user1", "mfa_enabled": false}],
		"password_policy": {"min_length": 14},
		"service_accounts": [],
	}}
	result.compliant == false
}

test_noncompliant_weak_password if {
	result := r8.result with input as {"normalized_data": {
		"users": [{"username": "user1", "mfa_enabled": true}],
		"password_policy": {"min_length": 8},
		"service_accounts": [],
	}}
	result.compliant == false
}
