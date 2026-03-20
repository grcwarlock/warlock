package pci_dss.r6_test

import rego.v1

import data.pci_dss.r6

test_compliant_secure_dev if {
	result := r6.result with input as {"normalized_data": {
		"vulnerabilities": [{"severity": "low", "title": "info-disclosure", "host": "web-01", "remediated": false}],
		"changes": [{"id": "CHG001", "environment": "production", "approved": true}],
	}}
	result.compliant == true
}

test_noncompliant_critical_vuln if {
	result := r6.result with input as {"normalized_data": {
		"vulnerabilities": [{"severity": "critical", "title": "rce-vuln", "host": "db-01", "remediated": false}],
		"changes": [],
	}}
	result.compliant == false
}
