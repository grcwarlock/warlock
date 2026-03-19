package nist.pe.pe_10_test

import rego.v1

import data.nist.pe.pe_10

test_compliant if {
	result := pe_10.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "emergency_shutoff_capability": true, "emergency_shutoff_accessible": true, "emergency_shutoff_tested_within_365_days": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_10.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "emergency_shutoff_capability": false}]}}}
	result.compliant == false
}
