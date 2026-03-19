package nist.ra.ra_5_test

import rego.v1

import data.nist.ra.ra_5

test_compliant_vuln_scanning_aws if {
	result := ra_5.result with input as {
		"provider": "aws",
		"normalized_data": {
			"inspector_enabled": true,
			"vulnerability_scan_schedule": {"last_scan_days": 5, "required_frequency_days": 30},
			"vulnerabilities": [],
			"uses_containers": false,
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_scanner_aws if {
	result := ra_5.result with input as {
		"provider": "aws",
		"normalized_data": {
			"vulnerability_scan_schedule": {"last_scan_days": 5, "required_frequency_days": 30},
			"vulnerabilities": [],
			"uses_containers": false,
		},
	}
	result.compliant == false
}
