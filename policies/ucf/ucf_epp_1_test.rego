package ucf.epp.ucf_epp_1_test

import rego.v1

import data.ucf.epp.ucf_epp_1

test_healthy_agents if {
	result := ucf_epp_1.result with input as {"normalized_data": {
		"endpoints": [
			{"hostname": "host1", "status": "online", "device_id": "d1"},
			{"hostname": "host2", "status": "online", "device_id": "d2"},
		],
	}}
	result.compliant == true
}

test_no_agents if {
	result := ucf_epp_1.result with input as {"normalized_data": {"endpoints": []}}
	result.compliant == false
}

test_stale_agent if {
	result := ucf_epp_1.result with input as {"normalized_data": {
		"endpoints": [{"hostname": "host1", "status": "offline", "device_id": "d1"}],
	}}
	result.compliant == false
}
