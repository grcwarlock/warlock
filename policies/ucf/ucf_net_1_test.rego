package ucf.net.ucf_net_1_test

import rego.v1

import data.ucf.net.ucf_net_1

test_no_open_sgs if {
	result := ucf_net_1.result with input as {"normalized_data": {
		"security_groups": [{"group_id": "sg-1", "issues": []}],
	}}
	result.compliant == true
}

test_open_sg if {
	result := ucf_net_1.result with input as {"normalized_data": {
		"security_groups": [{"group_id": "sg-1", "issues": ["open_to_world_port_22"]}],
	}}
	result.compliant == false
}
