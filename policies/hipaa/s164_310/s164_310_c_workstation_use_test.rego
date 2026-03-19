package hipaa.s164_310.s164_310_c_test

import rego.v1

import data.hipaa.s164_310.s164_310_c

test_compliant_workstation_use if {
	result := s164_310_c.result with input as {"normalized_data": {
		"policies": {
			"workstation_use_policy": true,
			"remote_workstation_policy": true,
		},
		"users": [
			{"username": "alice", "account_enabled": true, "ephi_access": true, "acceptable_use_signed": true},
		],
		"config": {"remote_access_enabled": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_acceptable_use_agreement if {
	result := s164_310_c.result with input as {"normalized_data": {
		"policies": {
			"workstation_use_policy": true,
			"remote_workstation_policy": true,
		},
		"users": [
			{"username": "bob", "account_enabled": true, "ephi_access": true, "acceptable_use_signed": false},
		],
		"config": {"remote_access_enabled": true},
	}}
	result.compliant == false
}
