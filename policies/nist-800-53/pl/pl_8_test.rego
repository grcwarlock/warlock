package nist.pl.pl_8_test

import rego.v1

import data.nist.pl.pl_8

test_compliant if {
	result := pl_8.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "security_architecture_documented": true, "architecture_reviewed_within_365_days": true, "threat_model_documented": true, "architecture_aligned_with_enterprise": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_8.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "security_architecture_documented": false, "threat_model_documented": false}]}}}
	result.compliant == false
}
