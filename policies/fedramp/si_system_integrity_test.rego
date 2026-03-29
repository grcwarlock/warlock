package warlock.fedramp.si_test

import rego.v1

import data.warlock.fedramp.si

test_compliant_system_integrity if {
	result := si.result with input as {"normalized_data": {
		"vulnerabilities": [
			{"id": "CVE-2025-001", "severity": "critical", "days_since_discovery": 10, "remediated": false},
			{"id": "CVE-2025-002", "severity": "high", "days_since_discovery": 45, "remediated": false},
		],
		"endpoint_protection": {"malware_scanning_enabled": true},
		"monitoring": {"system_monitoring_enabled": true},
		"vulnerability_management": {"advisory_monitoring_enabled": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_overdue_critical_patch if {
	result := si.result with input as {"normalized_data": {
		"vulnerabilities": [
			{"id": "CVE-2025-003", "severity": "critical", "days_since_discovery": 45, "remediated": false},
		],
		"endpoint_protection": {"malware_scanning_enabled": true},
		"monitoring": {"system_monitoring_enabled": true},
		"vulnerability_management": {"advisory_monitoring_enabled": true},
	}}
	result.compliant == false
}

test_no_malware_protection if {
	result := si.result with input as {"normalized_data": {
		"vulnerabilities": [],
		"endpoint_protection": {"malware_scanning_enabled": false},
		"monitoring": {"system_monitoring_enabled": true},
		"vulnerability_management": {"advisory_monitoring_enabled": true},
	}}
	result.compliant == false
}

test_remediated_vulns_pass if {
	result := si.result with input as {"normalized_data": {
		"vulnerabilities": [
			{"id": "CVE-2025-004", "severity": "critical", "days_since_discovery": 60, "remediated": true},
		],
		"endpoint_protection": {"malware_scanning_enabled": true},
		"monitoring": {"system_monitoring_enabled": true},
		"vulnerability_management": {"advisory_monitoring_enabled": true},
	}}
	result.compliant == true
}
