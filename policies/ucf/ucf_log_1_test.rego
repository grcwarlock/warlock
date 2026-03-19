package ucf.log.ucf_log_1_test

import rego.v1

import data.ucf.log.ucf_log_1

test_logging_enabled_multi_region if {
	result := ucf_log_1.result with input as {"normalized_data": {
		"cloudtrail": {"enabled": true, "multi_region": true, "trails": [{"name": "main"}]},
	}}
	result.compliant == true
}

test_no_logging if {
	result := ucf_log_1.result with input as {"normalized_data": {
		"cloudtrail": {"enabled": false, "multi_region": false, "trails": []},
	}}
	result.compliant == false
}

test_not_multi_region if {
	result := ucf_log_1.result with input as {"normalized_data": {
		"cloudtrail": {"enabled": true, "multi_region": false, "trails": [{"name": "main"}]},
	}}
	result.compliant == false
}
