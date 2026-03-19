package iso_27001.a8.a8_16_test

import rego.v1

import data.iso_27001.a8.a8_16

test_compliant_a8_16 if {
	result := a8_16.result with input as {"normalized_data": {
		"guardduty": {
			"enabled": true,
			"high_severity_finding_count": 0,
		},
		"security_hub": {
			"enabled": true,
		},
		"cloudwatch": {
			"anomaly_detectors_configured": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_16 if {
	result := a8_16.result with input as {"normalized_data": {}}
	result.compliant == false
}
