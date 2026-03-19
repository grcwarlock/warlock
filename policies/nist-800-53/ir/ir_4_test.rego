package nist.ir.ir_4_test

import rego.v1

import data.nist.ir.ir_4

test_compliant_incident_handling if {
	result := ir_4.result with input as {
		"provider": "aws",
		"normalized_data": {
			"incident_handling": {
				"detection_configured": true,
				"guardduty_enabled": true,
				"containment_procedures_documented": true,
				"eradication_procedures_documented": true,
				"recovery_procedures_documented": true,
				"incidents_occurred": false,
			},
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_incident_handling if {
	result := ir_4.result with input as {
		"provider": "aws",
		"normalized_data": {},
	}
	result.compliant == false
}
