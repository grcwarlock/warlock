package warlock.fedramp.sc_test

import rego.v1

import data.warlock.fedramp.sc

test_compliant_system_communications if {
	result := sc.result with input as {"normalized_data": {
		"network": {"interfaces": [{"id": "eni-1", "managed": true}]},
		"endpoints": [{"url": "https://api.gov.example.com", "fips_validated_encryption": true, "handles_federal_data": true}],
		"encryption": {"key_management_system": true, "fips_validated_modules": true},
		"storage": [{"id": "s3-federal", "contains_federal_data": true, "encryption_at_rest": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_fips_encryption if {
	result := sc.result with input as {"normalized_data": {
		"network": {"interfaces": []},
		"endpoints": [{"url": "https://api.example.com", "fips_validated_encryption": false, "handles_federal_data": true}],
		"encryption": {"key_management_system": true, "fips_validated_modules": true},
		"storage": [],
	}}
	result.compliant == false
}

test_no_key_management if {
	result := sc.result with input as {"normalized_data": {
		"network": {"interfaces": []},
		"endpoints": [],
		"encryption": {"key_management_system": false, "fips_validated_modules": true},
		"storage": [],
	}}
	result.compliant == false
}

test_unencrypted_federal_storage if {
	result := sc.result with input as {"normalized_data": {
		"network": {"interfaces": []},
		"endpoints": [],
		"encryption": {"key_management_system": true, "fips_validated_modules": true},
		"storage": [{"id": "ebs-vol", "contains_federal_data": true, "encryption_at_rest": false}],
	}}
	result.compliant == false
}
