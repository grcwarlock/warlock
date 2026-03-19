package nist.pe.pe_14_test

import rego.v1

import data.nist.pe.pe_14

test_compliant if {
	result := pe_14.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "contains_critical_systems": true, "temperature_monitoring_enabled": true, "humidity_monitoring_enabled": true}], "environmental_sensors": [{"sensor_id": "S-1", "facility_id": "DC-1", "sensor_type": "temperature", "current_value": 20, "max_threshold": 30, "alerting_enabled": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_14.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "contains_critical_systems": true, "temperature_monitoring_enabled": false, "humidity_monitoring_enabled": false}], "environmental_sensors": [{"sensor_id": "S-2", "facility_id": "DC-2", "sensor_type": "temperature", "current_value": 35, "max_threshold": 30, "alerting_enabled": false}]}}}
	result.compliant == false
}
