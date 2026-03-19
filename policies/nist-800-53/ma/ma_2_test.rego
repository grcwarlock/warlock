package nist.ma.ma_2_test

import rego.v1

import data.nist.ma.ma_2

test_compliant_controlled_maintenance if {
	result := ma_2.result with input as {"normalized_data": {
		"maintenance": {
			"schedule_defined": true,
			"activities": [
				{"activity_id": "MA-001", "target_system": "srv-01", "approved": true, "logged": true},
			],
			"systems": [
				{"system_id": "srv-01", "maintenance_records_kept": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unapproved if {
	result := ma_2.result with input as {"normalized_data": {
		"maintenance": {
			"schedule_defined": true,
			"activities": [
				{"activity_id": "MA-002", "target_system": "srv-02", "approved": false, "logged": false},
			],
			"systems": [{"system_id": "srv-02", "maintenance_records_kept": true}],
		},
	}}
	result.compliant == false
}
