package ucf.asm.ucf_asm_1_test

import rego.v1

import data.ucf.asm.ucf_asm_1

test_inventory_present if {
	result := ucf_asm_1.result with input as {"normalized_data": {
		"endpoints": [{"device_id": "d1", "hostname": "host1"}],
		"devices": [],
		"users": [{"username": "alice", "mfa_enabled": true}],
	}}
	result.compliant == true
}

test_no_inventory if {
	result := ucf_asm_1.result with input as {"normalized_data": {
		"endpoints": [],
		"devices": [],
		"users": [],
	}}
	result.compliant == false
}
