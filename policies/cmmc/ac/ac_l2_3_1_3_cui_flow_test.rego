package cmmc.ac.ac_l2_3_1_3_test

import rego.v1

import data.cmmc.ac.ac_l2_3_1_3

test_compliant_cui_flow if {
	result := ac_l2_3_1_3.result with input as {"normalized_data": {
		"networks": [
			{"name": "cui-net", "contains_cui": true, "segmented": true},
		],
		"systems": [
			{"name": "cui-server", "processes_cui": true, "dlp_enabled": true},
		],
		"security_groups": [
			{"name": "cui-sg", "cui_boundary": true, "egress_rules": [
				{"destination": "10.0.0.0/8", "protocol": "tcp"},
			]},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_network_segmentation if {
	result := ac_l2_3_1_3.result with input as {"normalized_data": {
		"networks": [
			{"name": "cui-net", "contains_cui": true, "segmented": false},
		],
		"systems": [
			{"name": "cui-server", "processes_cui": true, "dlp_enabled": true},
		],
		"security_groups": [],
	}}
	result.compliant == false
}
