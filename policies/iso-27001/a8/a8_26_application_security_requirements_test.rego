package iso_27001.a8.a8_26_test

import rego.v1

import data.iso_27001.a8.a8_26

test_compliant_a8_26 if {
	result := a8_26.result with input as {"normalized_data": {
		"inspector": {
			"lambda_scanning_enabled": true,
			"critical_app_finding_count": 0,
		},
		"policies": {
			"application_security_requirements_documented": true,
		},
		"waf": {
			"web_acls": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_26 if {
	result := a8_26.result with input as {"normalized_data": {}}
	result.compliant == false
}
