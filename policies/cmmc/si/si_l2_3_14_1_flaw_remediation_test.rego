package cmmc.si.si_l2_3_14_1_test

import rego.v1

import data.cmmc.si.si_l2_3_14_1

test_compliant_flaw_remediation if {
	result := si_l2_3_14_1.result with input as {"normalized_data": {
		"vulnerabilities": [
			{"cve_id": "CVE-2024-0001", "system_name": "prod-web", "severity": "critical", "age_days": 5},
		],
		"systems": [
			{"name": "prod-web", "patch_management_enabled": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_critical_vulnerability_overdue if {
	result := si_l2_3_14_1.result with input as {"normalized_data": {
		"vulnerabilities": [
			{"cve_id": "CVE-2024-0001", "system_name": "prod-web", "severity": "critical", "age_days": 30},
		],
		"systems": [
			{"name": "prod-web", "patch_management_enabled": true},
		],
	}}
	result.compliant == false
}
