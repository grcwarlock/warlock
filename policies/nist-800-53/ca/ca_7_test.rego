package nist.ca.ca_7_test

import rego.v1

import data.nist.ca.ca_7

test_compliant_continuous_monitoring if {
	result := ca_7.result with input as {
		"provider": "aws",
		"normalized_data": {
			"continuous_monitoring": {
				"vulnerability_scanning_enabled": true,
				"last_vulnerability_scan_days": 10,
				"aws_config_enabled": true,
				"security_hub_enabled": true,
				"reporting_configured": true,
				"automated_alerting": true,
			},
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_monitoring if {
	result := ca_7.result with input as {
		"provider": "aws",
		"normalized_data": {},
	}
	result.compliant == false
}
