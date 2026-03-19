package iso_27001.a5.a5_07_test

import rego.v1

import data.iso_27001.a5.a5_07

test_compliant_a5_07 if {
	result := a5_07.result with input as {"normalized_data": {
		"guardduty": {
			"enabled": true,
			"malware_protection_enabled": true,
			"high_severity_finding_count": 0,
			"threat_intel_sets": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_07 if {
	result := a5_07.result with input as {"normalized_data": {}}
	result.compliant == false
}
