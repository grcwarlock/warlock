package nist.pe.pe_13_test

import rego.v1

import data.nist.pe.pe_13

test_compliant if {
	result := pe_13.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "fire_detection_system_installed": true, "contains_critical_systems": true, "fire_suppression_system_installed": true, "fire_system_tested_within_365_days": true, "fire_alarm_connected_to_notification": true, "fire_marshal_inspection_current": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_13.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "fire_detection_system_installed": false, "contains_critical_systems": true, "fire_suppression_system_installed": false, "fire_marshal_inspection_current": false}]}}}
	result.compliant == false
}
