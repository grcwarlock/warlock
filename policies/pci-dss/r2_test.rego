package pci_dss.r2_test

import rego.v1

import data.pci_dss.r2

test_compliant_config if {
	result := r2.result with input as {"normalized_data": {"systems": [
		{"name": "web-01", "default_credentials_present": false, "unnecessary_services": []},
	]}}
	result.compliant == true
}

test_noncompliant_default_creds if {
	result := r2.result with input as {"normalized_data": {"systems": [
		{"name": "db-01", "default_credentials_present": true, "unnecessary_services": []},
	]}}
	result.compliant == false
}
