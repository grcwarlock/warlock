package nist.ma.ma_4_test

import rego.v1

import data.nist.ma.ma_4

test_compliant_nonlocal_maintenance if {
	result := ma_4.result with input as {"normalized_data": {
		"maintenance": {
			"remote_sessions": [
				{"session_id": "RS-001", "target_system": "srv-01", "encrypted": true, "mfa_used": true, "audited": true, "pre_authorized": true, "status": "completed", "within_approved_window": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_encryption if {
	result := ma_4.result with input as {"normalized_data": {
		"maintenance": {
			"remote_sessions": [
				{"session_id": "RS-002", "target_system": "srv-02", "encrypted": false, "mfa_used": false, "audited": false, "pre_authorized": false, "status": "active", "within_approved_window": false},
			],
		},
	}}
	result.compliant == false
}
