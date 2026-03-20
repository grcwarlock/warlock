package pci_dss.r4_test

import rego.v1

import data.pci_dss.r4

test_compliant_transit if {
	result := r4.result with input as {"normalized_data": {"endpoints": [
		{"name": "api.example.com", "tls_version": "TLSv1.3", "encryption_in_transit": true},
	]}}
	result.compliant == true
}

test_noncompliant_weak_tls if {
	result := r4.result with input as {"normalized_data": {"endpoints": [
		{"name": "legacy.example.com", "tls_version": "TLSv1.0", "encryption_in_transit": true},
	]}}
	result.compliant == false
}
