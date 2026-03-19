package hipaa.s164_312.s164_312_e_1_test

import rego.v1

import data.hipaa.s164_312.s164_312_e_1

test_compliant_transmission_security if {
	result := s164_312_e_1.result with input as {"normalized_data": {
		"config": {
			"tls_enforced": true,
			"min_tls_version": "1.2",
			"transmission_integrity_checks": true,
		},
		"resources": {"endpoints": [
			{"name": "api-prod", "handles_ephi": true, "encryption_in_transit": true},
		]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_tls_enforcement if {
	result := s164_312_e_1.result with input as {"normalized_data": {
		"config": {
			"tls_enforced": false,
			"min_tls_version": "1.0",
			"transmission_integrity_checks": false,
		},
		"resources": {"endpoints": [
			{"name": "api-prod", "handles_ephi": true, "encryption_in_transit": false},
		]},
	}}
	result.compliant == false
}
