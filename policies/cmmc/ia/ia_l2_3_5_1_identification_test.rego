package cmmc.ia.ia_l2_3_5_1_test

import rego.v1

import data.cmmc.ia.ia_l2_3_5_1

test_compliant_identification if {
	result := ia_l2_3_5_1.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "shared_account": false, "service_account": false, "owner_assigned": true},
		],
		"devices": [
			{"name": "laptop-001", "identified": true, "certificate_bound": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_shared_account if {
	result := ia_l2_3_5_1.result with input as {"normalized_data": {
		"users": [
			{"username": "shared-ops", "shared_account": true, "service_account": false, "owner_assigned": true},
		],
		"devices": [
			{"name": "laptop-001", "identified": true, "certificate_bound": true},
		],
	}}
	result.compliant == false
}
