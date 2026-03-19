package nist.ca.ca_8_test

import rego.v1

import data.nist.ca.ca_8

test_compliant_pentest if {
	result := ca_8.result with input as {"normalized_data": {
		"penetration_testing": {
			"last_test_days": 180,
			"report_available": true,
			"critical_findings_open": 0,
			"scope_defined": true,
			"findings_total": 5,
			"remediation_tracked": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_pentest if {
	result := ca_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
