package cmmc.sc.sc_l2_3_13_8_test

import rego.v1

import data.cmmc.sc.sc_l2_3_13_8

test_compliant_transmission_confidentiality if {
	result := sc_l2_3_13_8.result with input as {"normalized_data": {
		"systems": [
			{"name": "cui-server", "processes_cui": true, "tls_enforced": true, "minimum_tls_version": "1.2"},
		],
		"endpoints": [
			{"url": "https://api.example.com", "handles_cui": true, "encryption_in_transit": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_tls_on_cui_system if {
	result := sc_l2_3_13_8.result with input as {"normalized_data": {
		"systems": [
			{"name": "cui-server", "processes_cui": true, "tls_enforced": false, "minimum_tls_version": "1.0"},
		],
		"endpoints": [
			{"url": "http://api.example.com", "handles_cui": true, "encryption_in_transit": false},
		],
	}}
	result.compliant == false
}
