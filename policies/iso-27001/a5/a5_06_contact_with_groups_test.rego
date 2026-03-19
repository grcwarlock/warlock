package iso_27001.a5.a5_06_test

import rego.v1

import data.iso_27001.a5.a5_06

test_compliant_a5_06 if {
	result := a5_06.result with input as {"normalized_data": {
		"security_hub": {
			"threat_intel_feeds_enabled": true,
			"enabled_products": ["item1"],
		},
		"support": {
			"trusted_advisor_enabled": true,
		},
		"sns": {
			"security_bulletin_subscription": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_06 if {
	result := a5_06.result with input as {"normalized_data": {}}
	result.compliant == false
}
