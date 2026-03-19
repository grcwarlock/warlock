package ucf.rsk.ucf_rsk_4_test

import rego.v1

import data.ucf.rsk.ucf_rsk_4

test_monitoring_enabled if {
	result := ucf_rsk_4.result with input as {"normalized_data": {
		"config": {"enabled": true, "recorders": [{"name": "default"}]},
		"guardduty_enabled": true,
	}}
	result.compliant == true
}

test_no_monitoring if {
	result := ucf_rsk_4.result with input as {"normalized_data": {
		"config": {"enabled": false, "recorders": []},
		"guardduty_enabled": false,
	}}
	result.compliant == false
}

test_partial_monitoring if {
	result := ucf_rsk_4.result with input as {"normalized_data": {
		"config": {"enabled": true, "recorders": [{"name": "default"}]},
		"guardduty_enabled": false,
	}}
	result.compliant == false
}
