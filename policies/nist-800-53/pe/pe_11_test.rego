package nist.pe.pe_11_test

import rego.v1

import data.nist.pe.pe_11

test_compliant if {
	result := pe_11.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "contains_critical_systems": true, "ups_installed": true, "backup_generator_installed": true, "ups_tested_within_180_days": true, "generator_tested_within_90_days": true, "ups_runtime_minutes": 30}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_11.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "contains_critical_systems": true, "ups_installed": false, "backup_generator_installed": false}]}}}
	result.compliant == false
}
