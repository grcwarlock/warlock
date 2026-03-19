package nist.ma.ma_5_test

import rego.v1

import data.nist.ma.ma_5

test_compliant_maintenance_personnel if {
	result := ma_5.result with input as {"normalized_data": {
		"maintenance": {
			"authorized_personnel_list_defined": true,
			"personnel": [
				{"person_id": "MP-001", "authorized": true, "background_check_completed": true, "credentials_expired": false, "external": false, "supervised": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unauthorized if {
	result := ma_5.result with input as {"normalized_data": {
		"maintenance": {
			"authorized_personnel_list_defined": true,
			"personnel": [
				{"person_id": "MP-002", "authorized": false, "background_check_completed": false, "credentials_expired": false, "external": false},
			],
		},
	}}
	result.compliant == false
}
