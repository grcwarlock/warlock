package nist.ca.ca_2_test

import rego.v1

import data.nist.ca.ca_2

test_compliant_control_assessments if {
	result := ca_2.result with input as {"normalized_data": {
		"control_assessments": {
			"last_assessment_days": 180,
			"assessment_plan_exists": true,
			"assessor_assigned": true,
			"report_generated": true,
			"open_findings": 0,
			"findings_remediation_overdue": false,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_assessment if {
	result := ca_2.result with input as {"normalized_data": {}}
	result.compliant == false
}
