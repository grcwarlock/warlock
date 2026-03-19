package cmmc.cm.cm_l2_3_4_6_test

import rego.v1

import data.cmmc.cm.cm_l2_3_4_6

test_compliant_least_functionality if {
	result := cm_l2_3_4_6.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "running_services": [{"name": "nginx", "essential": true}], "processes_cui": true, "software_allowlist_enforced": true},
		],
		"security_groups": [
			{"name": "web-sg", "ingress_rules": [{"port_range": "443"}]},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unnecessary_services if {
	result := cm_l2_3_4_6.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "running_services": [{"name": "telnet", "essential": false}], "processes_cui": true, "software_allowlist_enforced": true},
		],
		"security_groups": [],
	}}
	result.compliant == false
}
