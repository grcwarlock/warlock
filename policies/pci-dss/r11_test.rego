package pci_dss.r11_test

import rego.v1

import data.pci_dss.r11

test_compliant_testing if {
	result := r11.result with input as {"normalized_data": {
		"vulnerability_scanning": {"last_scan_days_ago": 7, "critical_findings": []},
		"intrusion_detection": {"enabled": true},
	}}
	result.compliant == true
}

test_noncompliant_stale_scan if {
	result := r11.result with input as {"normalized_data": {
		"vulnerability_scanning": {"last_scan_days_ago": 120, "critical_findings": []},
		"intrusion_detection": {"enabled": true},
	}}
	result.compliant == false
}

test_noncompliant_no_ids if {
	result := r11.result with input as {"normalized_data": {
		"vulnerability_scanning": {"last_scan_days_ago": 7, "critical_findings": []},
		"intrusion_detection": {"enabled": false},
	}}
	result.compliant == false
}
