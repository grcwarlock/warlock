package hipaa.s164_308.s164_308_a_6_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_6

test_compliant_incident_procedures if {
	result := s164_308_a_6.result with input as {"normalized_data": {
		"policies": {
			"incident_response_plan": true,
			"breach_notification_procedure": true,
		},
		"config": {"security_incident_logging_enabled": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_incident_response_plan if {
	result := s164_308_a_6.result with input as {"normalized_data": {
		"policies": {
			"incident_response_plan": false,
			"breach_notification_procedure": false,
		},
		"config": {"security_incident_logging_enabled": false},
	}}
	result.compliant == false
}
