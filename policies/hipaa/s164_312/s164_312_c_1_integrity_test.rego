package hipaa.s164_312.s164_312_c_1_test

import rego.v1

import data.hipaa.s164_312.s164_312_c_1

test_compliant_integrity if {
	result := s164_312_c_1.result with input as {"normalized_data": {
		"config": {"integrity_verification_enabled": true},
		"resources": {"datastores": [
			{"name": "db-prod", "contains_ephi": true, "versioning_enabled": true, "checksum_validation": true},
		]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_versioning if {
	result := s164_312_c_1.result with input as {"normalized_data": {
		"config": {"integrity_verification_enabled": true},
		"resources": {"datastores": [
			{"name": "db-prod", "contains_ephi": true, "versioning_enabled": false, "checksum_validation": true},
		]},
	}}
	result.compliant == false
}
