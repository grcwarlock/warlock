package nist.pe.pe_15_test

import rego.v1

import data.nist.pe.pe_15

test_compliant if {
	result := pe_15.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "contains_critical_systems": true, "water_detection_sensors_installed": true, "water_shutoff_valves_accessible": true, "below_grade": false}], "environmental_sensors": [{"sensor_id": "W-1", "facility_id": "DC-1", "sensor_type": "water", "actively_monitored": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_15.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "contains_critical_systems": true, "water_detection_sensors_installed": false, "water_shutoff_valves_accessible": false, "below_grade": true, "adequate_drainage": false}], "environmental_sensors": []}}}
	result.compliant == false
}
