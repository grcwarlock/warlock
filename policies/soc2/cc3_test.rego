package soc2.cc3_test

import rego.v1

import data.soc2.cc3

test_compliant_risk_assessment if {
	result := cc3.result with input as {"normalized_data": {"governance": {
		"risk_assessment_performed": true,
		"risk_assessment_age_days": 100,
		"risk_register_entries": 5,
		"risks": [{"name": "R1", "severity": "high", "mitigation_plan_exists": true}],
		"fraud_risk_assessment_exists": true,
		"fraud_controls_implemented": true,
		"change_risk_tracking_enabled": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_risk_assessment if {
	result := cc3.result with input as {"normalized_data": {"governance": {
		"risk_register_entries": 0,
		"risks": [],
	}}}
	result.compliant == false
}
