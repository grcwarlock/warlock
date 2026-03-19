package cmmc.cm.cm_l2_3_4_2_test

import rego.v1

import data.cmmc.cm.cm_l2_3_4_2

test_compliant_change_control if {
	result := cm_l2_3_4_2.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "security_hardening_applied": true, "default_credentials_present": false},
		],
		"configuration_changes": [
			{"description": "Update TLS config", "system_name": "prod-web", "approved": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_default_credentials if {
	result := cm_l2_3_4_2.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "security_hardening_applied": true, "default_credentials_present": true},
		],
		"configuration_changes": [],
	}}
	result.compliant == false
}
