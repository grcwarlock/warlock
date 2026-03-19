package nist.pe.pe_12_test

import rego.v1

import data.nist.pe.pe_12

test_compliant if {
	result := pe_12.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "emergency_lighting_installed": true, "emergency_lighting_tested_within_365_days": true, "emergency_lighting_covers_exits": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_12.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "emergency_lighting_installed": false}]}}}
	result.compliant == false
}
