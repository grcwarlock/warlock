package warlock.fedramp_test

import rego.v1

import data.warlock.fedramp

test_compliant_fedramp_baseline if {
	result := fedramp.result with input as {"normalized_data": {
		"account_management": {"automated_lifecycle": true},
		"audit": {"captured_events": ["login", "logout", "access_denied", "privilege_change", "data_access"]},
		"vulnerability_management": {"continuous_scanning_enabled": true},
		"network": {"boundary_protection_enabled": true},
		"monitoring": {"continuous_monitoring_plan": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_missing_audit_events if {
	result := fedramp.result with input as {"normalized_data": {
		"account_management": {"automated_lifecycle": true},
		"audit": {"captured_events": ["login", "logout"]},
		"vulnerability_management": {"continuous_scanning_enabled": true},
		"network": {"boundary_protection_enabled": true},
		"monitoring": {"continuous_monitoring_plan": true},
	}}
	result.compliant == false
}

test_no_boundary_protection if {
	result := fedramp.result with input as {"normalized_data": {
		"account_management": {"automated_lifecycle": true},
		"audit": {"captured_events": ["login", "logout", "access_denied", "privilege_change", "data_access"]},
		"vulnerability_management": {"continuous_scanning_enabled": true},
		"network": {"boundary_protection_enabled": false},
		"monitoring": {"continuous_monitoring_plan": true},
	}}
	result.compliant == false
}

test_no_continuous_monitoring if {
	result := fedramp.result with input as {"normalized_data": {
		"account_management": {"automated_lifecycle": true},
		"audit": {"captured_events": ["login", "logout", "access_denied", "privilege_change", "data_access"]},
		"vulnerability_management": {"continuous_scanning_enabled": true},
		"network": {"boundary_protection_enabled": true},
		"monitoring": {"continuous_monitoring_plan": false},
	}}
	result.compliant == false
}
