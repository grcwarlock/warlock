package nist.sa.sa_11_test

import rego.v1

import data.nist.sa.sa_11

test_compliant_dev_testing if {
	result := sa_11.result with input as {"normalized_data": {
		"sast_configured": true,
		"dast_configured": true,
		"cicd_security_gates": {"bypass_allowed": false},
		"sast_in_pipeline": true,
		"dependency_scanning_configured": true,
		"security_test_plan": true,
		"pipeline_security_findings": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_sast if {
	result := sa_11.result with input as {"normalized_data": {
		"pipeline_security_findings": [],
	}}
	result.compliant == false
}
