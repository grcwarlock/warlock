package gdpr.art32_test

import rego.v1

import data.gdpr.art32

test_compliant_security_of_processing if {
	result := art32.result with input as {"normalized_data": {
		"storage_resources": [{"name": "db-prod", "encryption_enabled": true}],
		"users": [{"username": "alice", "mfa_enabled": true}],
		"security_groups": [{"name": "sg-web", "ingress_rules": [{"cidr": "10.0.0.0/8", "port_range_low": 443, "port_range_high": 443}]}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_encryption if {
	result := art32.result with input as {"normalized_data": {
		"storage_resources": [{"name": "bucket-pii", "encryption_enabled": false}],
		"users": [{"username": "alice", "mfa_enabled": true}],
		"security_groups": [],
	}}
	result.compliant == false
}

test_no_mfa if {
	result := art32.result with input as {"normalized_data": {
		"storage_resources": [],
		"users": [{"username": "bob", "mfa_enabled": false}],
		"security_groups": [],
	}}
	result.compliant == false
}

test_open_ssh if {
	result := art32.result with input as {"normalized_data": {
		"storage_resources": [],
		"users": [],
		"security_groups": [{"name": "sg-bad", "ingress_rules": [{"cidr": "0.0.0.0/0", "port_range_low": 22, "port_range_high": 22}]}],
	}}
	result.compliant == false
}
