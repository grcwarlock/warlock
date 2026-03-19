package cmmc.sc.sc_l2_3_13_1_test

import rego.v1

import data.cmmc.sc.sc_l2_3_13_1

test_compliant_boundary_protection if {
	result := sc_l2_3_13_1.result with input as {"normalized_data": {
		"security_groups": [
			{"name": "web-sg", "ingress_rules": [
				{"source": "0.0.0.0/0", "port_range": "443"},
			]},
		],
		"systems": [
			{"name": "prod-web", "internet_facing": true, "waf_enabled": true},
		],
		"networks": [
			{"name": "cui-net", "contains_cui": true, "intrusion_detection_enabled": true, "traffic_monitoring_enabled": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unrestricted_ingress if {
	result := sc_l2_3_13_1.result with input as {"normalized_data": {
		"security_groups": [
			{"name": "web-sg", "ingress_rules": [
				{"source": "0.0.0.0/0", "port_range": "22"},
			]},
		],
		"systems": [
			{"name": "prod-web", "internet_facing": true, "waf_enabled": true},
		],
		"networks": [
			{"name": "cui-net", "contains_cui": true, "intrusion_detection_enabled": true, "traffic_monitoring_enabled": true},
		],
	}}
	result.compliant == false
}
