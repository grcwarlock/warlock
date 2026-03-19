package iso_27001.a5.a5_28_test

import rego.v1

import data.iso_27001.a5.a5_28

test_compliant_a5_28 if {
	result := a5_28.result with input as {"normalized_data": {
		"cloudtrail": {
			"log_file_validation_enabled": true,
		},
		"policies": {
			"forensic_evidence_procedure_documented": true,
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_28 if {
	result := a5_28.result with input as {"normalized_data": {
		"s3": {"buckets": [{"name": "log-bucket", "purpose": "logs", "object_lock_enabled": false, "encryption_enabled": false}]},
		"cloudtrail": {"enabled": true, "log_file_validation_enabled": false},
		"policies": {"forensic_evidence_procedure_documented": false},
	}}
	result.compliant == false
}
