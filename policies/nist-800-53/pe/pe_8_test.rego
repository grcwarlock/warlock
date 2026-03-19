package nist.pe.pe_8_test

import rego.v1

import data.nist.pe.pe_8

test_compliant if {
	result := pe_8.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "visitor_log_maintained": true, "visitor_log_reviewed_within_90_days": true, "visitor_log_retention_days": 365}], "visitors": [{"visitor_id": "VIS-1", "facility_id": "DC-1", "escorted": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_8.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "visitor_log_maintained": false, "visitor_log_retention_days": 30}], "visitors": [{"visitor_id": "VIS-2", "facility_id": "DC-2", "escorted": false, "escort_exemption": false}]}}}
	result.compliant == false
}
