package cmmc.ir.ir_l2_3_6_2_test

import rego.v1

import data.cmmc.ir.ir_l2_3_6_2

test_compliant_incident_reporting if {
	result := ir_l2_3_6_2.result with input as {"normalized_data": {
		"org_units": [
			{"name": "engineering", "incident_tracking_system": true},
		],
		"incidents": [
			{"id": "INC-001", "status": "closed", "age_days": 5, "involves_cui": true, "reported_to_dibcac": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unreported_cui_incident if {
	result := ir_l2_3_6_2.result with input as {"normalized_data": {
		"org_units": [
			{"name": "engineering", "incident_tracking_system": true},
		],
		"incidents": [
			{"id": "INC-002", "status": "open", "age_days": 5, "involves_cui": true, "reported_to_dibcac": false},
		],
	}}
	result.compliant == false
}
