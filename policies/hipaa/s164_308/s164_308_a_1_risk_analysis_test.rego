package hipaa.s164_308.s164_308_a_1_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_1

test_compliant_risk_assessment if {
	result := s164_308_a_1.result with input as {"normalized_data": {"risk_assessment": {
		"completed": true,
		"last_review_days": 100,
		"scope_documented": true,
		"remediation_plan_exists": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_risk_assessment if {
	result := s164_308_a_1.result with input as {"normalized_data": {"risk_assessment": {
		"completed": false,
		"last_review_days": 0,
		"scope_documented": false,
		"remediation_plan_exists": false,
	}}}
	result.compliant == false
}
