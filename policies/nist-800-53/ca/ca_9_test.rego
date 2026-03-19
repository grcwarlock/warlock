package nist.ca.ca_9_test

import rego.v1

import data.nist.ca.ca_9

test_compliant_internal_connections if {
	result := ca_9.result with input as {
		"provider": "aws",
		"normalized_data": {
			"internal_connections": [
				{"source": "app-server", "destination": "db-server", "authorized": true, "interface_documented": true, "last_review_days": 100},
			],
			"network_segmentation_enabled": true,
			"security_groups": [],
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_inventory if {
	result := ca_9.result with input as {
		"provider": "aws",
		"normalized_data": {
			"security_groups": [],
			"network_segmentation_enabled": true,
		},
	}
	result.compliant == false
}
