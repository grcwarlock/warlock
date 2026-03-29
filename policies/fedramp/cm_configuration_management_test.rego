package warlock.fedramp.cm_test

import rego.v1

import data.warlock.fedramp.cm

test_compliant_config_management if {
	result := cm.result with input as {"normalized_data": {
		"configuration": {
			"baseline_documented": true,
			"recent_changes": [{"id": "CHG-001", "approved": true}],
			"systems": [{"id": "web-01", "hardened": true, "unnecessary_services": []}],
			"component_inventory_maintained": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unapproved_change if {
	result := cm.result with input as {"normalized_data": {
		"configuration": {
			"baseline_documented": true,
			"recent_changes": [{"id": "CHG-002", "approved": false}],
			"systems": [],
			"component_inventory_maintained": true,
		},
	}}
	result.compliant == false
}

test_no_baseline if {
	result := cm.result with input as {"normalized_data": {
		"configuration": {
			"baseline_documented": false,
			"recent_changes": [],
			"systems": [],
			"component_inventory_maintained": true,
		},
	}}
	result.compliant == false
}

test_unnecessary_services if {
	result := cm.result with input as {"normalized_data": {
		"configuration": {
			"baseline_documented": true,
			"recent_changes": [],
			"systems": [{"id": "db-01", "hardened": true, "unnecessary_services": [{"name": "telnet", "enabled": true}]}],
			"component_inventory_maintained": true,
		},
	}}
	result.compliant == false
}
