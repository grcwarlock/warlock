package soc2.cc9_test

import rego.v1

import data.soc2.cc9

test_compliant_risk_mitigation if {
	result := cc9.result with input as {"normalized_data": {"governance": {
		"risk_treatment_plans_exist": true,
		"risks": [{"name": "R1", "severity": "high", "treatment_defined": true}],
		"vendor_management_program_exists": true,
		"vendors": [{"name": "V1", "risk_assessment_current": true, "critical": true, "sla_defined": true}],
		"cyber_insurance_exists": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_treatment if {
	result := cc9.result with input as {"normalized_data": {"governance": {
		"risks": [],
		"vendors": [],
	}}}
	result.compliant == false
}
