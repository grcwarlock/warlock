package nist.cm.cm_6_test

import rego.v1

import data.nist.cm.cm_6

test_compliant_configuration if {
	result := cm_6.result with input as {"normalized_data": {
		"rules": [
			{"direction": "inbound", "source": "10.0.0.0/8", "port_range": [443, 443], "group_name": "internal-sg"},
		],
		"resources": [
			{"resource_id": "vol-123", "resource_type": "ebs", "encrypted": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unencrypted_resource if {
	result := cm_6.result with input as {"normalized_data": {
		"rules": [],
		"resources": [
			{"resource_id": "vol-456", "resource_type": "ebs", "encrypted": false},
		],
	}}
	result.compliant == false
}
