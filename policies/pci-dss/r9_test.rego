package pci_dss.r9_test

import rego.v1

import data.pci_dss.r9

test_compliant_physical if {
	result := r9.result with input as {"normalized_data": {"physical_areas": [
		{"name": "server-room", "contains_cardholder_data": true, "access_control_enabled": true, "visitor_log_active": true},
	]}}
	result.compliant == true
}

test_noncompliant_no_access_control if {
	result := r9.result with input as {"normalized_data": {"physical_areas": [
		{"name": "office", "contains_cardholder_data": true, "access_control_enabled": false, "visitor_log_active": true},
	]}}
	result.compliant == false
}
