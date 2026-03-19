package nist.sc.sc_28_test

import rego.v1

import data.nist.sc.sc_28

test_compliant if {
	result := sc_28.result with input as {"normalized_data": {"resources": [{"resource_id": "vol-1", "resource_type": "ebs", "encrypted": true, "encryption_type": "SSE-KMS"}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := sc_28.result with input as {"normalized_data": {"resources": [{"resource_id": "vol-2", "resource_type": "ebs", "encrypted": false}]}}
	result.compliant == false
}
