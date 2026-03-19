package hipaa.s164_310.s164_310_b_test

import rego.v1

import data.hipaa.s164_310.s164_310_b

test_compliant_workstation_security if {
	result := s164_310_b.result with input as {"normalized_data": {
		"policies": {"workstation_security_policy": true},
		"resources": {"workstations": [
			{"name": "ws-001", "disk_encryption_enabled": true, "screen_lock_enabled": true},
		]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unencrypted_workstation if {
	result := s164_310_b.result with input as {"normalized_data": {
		"policies": {"workstation_security_policy": true},
		"resources": {"workstations": [
			{"name": "ws-001", "disk_encryption_enabled": false, "screen_lock_enabled": true},
		]},
	}}
	result.compliant == false
}
