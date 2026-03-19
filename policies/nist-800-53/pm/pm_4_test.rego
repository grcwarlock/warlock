package nist.pm.pm_4_test

import rego.v1

import data.nist.pm.pm_4

test_compliant_poam if {
	result := pm_4.result with input as {"normalized_data": {
		"poam_process": {
			"last_review_days": 15,
			"reporting_to_leadership": true,
		},
		"poams": [{"system_name": "sys1", "has_milestones": true, "items": [{"status": "closed", "days_past_due": 0, "finding_id": "F1"}]}],
		"security_findings": [{"id": "F1", "severity": "critical", "tracked_in_poam": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_poam if {
	result := pm_4.result with input as {"normalized_data": {}}
	result.compliant == false
}
