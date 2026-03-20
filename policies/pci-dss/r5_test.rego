package pci_dss.r5_test

import rego.v1

import data.pci_dss.r5

test_compliant_endpoints if {
	result := r5.result with input as {"normalized_data": {"endpoints": [
		{"hostname": "web-01", "antimalware_installed": true, "antimalware_current": true, "agent_status": "online"},
	]}}
	result.compliant == true
}

test_noncompliant_no_antimalware if {
	result := r5.result with input as {"normalized_data": {"endpoints": [
		{"hostname": "db-01", "antimalware_installed": false, "antimalware_current": false, "agent_status": "offline"},
	]}}
	result.compliant == false
}

test_noncompliant_agent_offline if {
	result := r5.result with input as {"normalized_data": {"endpoints": [
		{"hostname": "app-01", "antimalware_installed": true, "antimalware_current": true, "agent_status": "offline"},
	]}}
	result.compliant == false
}
