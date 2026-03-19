package cmmc.cm.cm_l2_3_4_1_test

import rego.v1

import data.cmmc.cm.cm_l2_3_4_1

test_compliant_baseline_config if {
	result := cm_l2_3_4_1.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "baseline_configuration_documented": true, "configuration_drift_detected": false, "in_asset_inventory": true},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_config_drift if {
	result := cm_l2_3_4_1.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "baseline_configuration_documented": true, "configuration_drift_detected": true, "in_asset_inventory": true},
	]}}
	result.compliant == false
}
