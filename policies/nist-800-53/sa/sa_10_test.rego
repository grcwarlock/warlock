package nist.sa.sa_10_test

import rego.v1

import data.nist.sa.sa_10

test_compliant_config_mgmt if {
	result := sa_10.result with input as {"normalized_data": {"developer_config_management": {
		"version_control_used": true,
		"change_tracking_enabled": true,
		"integrity_verification": true,
		"configuration_baseline_established": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_config_mgmt if {
	result := sa_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
