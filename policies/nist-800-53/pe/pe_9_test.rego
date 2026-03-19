package nist.pe.pe_9_test

import rego.v1

import data.nist.pe.pe_9

test_compliant if {
	result := pe_9.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-1", "power_equipment_protected": true, "power_room_access_controlled": true, "power_cabling_exposed": false}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_9.result with input as {"normalized_data": {"physical_security": {"facilities": [{"facility_id": "DC-2", "power_equipment_protected": false, "power_room_access_controlled": false, "power_cabling_exposed": true}]}}}
	result.compliant == false
}
