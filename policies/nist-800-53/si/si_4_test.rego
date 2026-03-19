package nist.si.si_4_test

import rego.v1

import data.nist.si.si_4

test_compliant if {
	result := si_4.result with input as {"provider": "aws", "normalized_data": {"guardduty_enabled": true, "security_hub_enabled": true}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := si_4.result with input as {"provider": "aws", "normalized_data": {"guardduty_enabled": false, "security_hub_enabled": false}}
	result.compliant == false
}
