package soc2.cc7_test

import rego.v1

import data.soc2.cc7

test_compliant_system_ops if {
	result := cc7.result with input as {
		"provider": "aws",
		"normalized_data": {
			"guardduty_enabled": true,
			"security_hub_enabled": true,
			"trails": [{"is_multi_region": true, "is_logging": true}],
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_monitoring if {
	result := cc7.result with input as {
		"provider": "aws",
		"normalized_data": {
			"trails": [],
		},
	}
	result.compliant == false
}
