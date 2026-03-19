package nist.pe.pe_6_test

import rego.v1

import data.nist.pe.pe_6

test_compliant if {
	result := pe_6.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "surveillance_system_installed": true, "surveillance_actively_monitored": true, "high_security": true, "intrusion_detection_system": true, "access_logs_maintained": true, "access_logs_reviewed_regularly": true, "physical_incident_response_procedure": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_6.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "surveillance_system_installed": false, "high_security": true, "intrusion_detection_system": false, "access_logs_maintained": false, "physical_incident_response_procedure": false}]}}}
	result.compliant == false
}
