package iso_27001.a5.a5_26_test

import rego.v1

import data.iso_27001.a5.a5_26

test_compliant_a5_26 if {
	result := a5_26.result with input as {"normalized_data": {
		"ssm": {
			"ir_automation_documents_exist": true,
		},
		"detective": {
			"enabled": true,
		},
		"config": {
			"auto_remediation_configured": true,
		},
		"policies": {
			"incident_response_procedure_documented": true,
		},
		"security_hub": {
			"total_findings_count": 0,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_26 if {
	result := a5_26.result with input as {"normalized_data": {}}
	result.compliant == false
}
