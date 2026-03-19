package nist.pe.pe_3_test

import rego.v1

import data.nist.pe.pe_3

test_compliant_physical_access if {
	result := pe_3.result with input as {"normalized_data": {
		"physical_security": {
			"facilities": [{"facility_id": "DC-1", "entry_control_mechanism": true, "access_logs_maintained": true}],
			"entry_points": [{"entry_point_id": "EP-1", "facility_id": "DC-1", "guard_posted": true, "automated_system": true, "high_security": true, "anti_tailgating_controls": true, "lock_mechanism": true}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_entry_control if {
	result := pe_3.result with input as {"normalized_data": {
		"physical_security": {
			"facilities": [{"facility_id": "DC-1", "entry_control_mechanism": false, "access_logs_maintained": false}],
			"entry_points": [{"entry_point_id": "EP-1", "facility_id": "DC-1", "guard_posted": false, "automated_system": false, "high_security": false, "lock_mechanism": false}],
		},
	}}
	result.compliant == false
}
