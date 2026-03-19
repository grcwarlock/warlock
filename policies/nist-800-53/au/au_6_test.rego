package nist.au.au_6_test

import rego.v1

import data.nist.au.au_6

test_compliant_aws_audit_review if {
	result := au_6.result with input as {
		"provider": "aws",
		"normalized_data": {
			"guardduty_enabled": true,
			"security_hub_enabled": true,
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_guardduty if {
	result := au_6.result with input as {
		"provider": "aws",
		"normalized_data": {
			"guardduty_enabled": false,
			"security_hub_enabled": true,
		},
	}
	result.compliant == false
}
