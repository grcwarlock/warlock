package ucf.hrs.ucf_hrs_1_test

import rego.v1

import data.ucf.hrs.ucf_hrs_1

test_all_screened if {
	result := ucf_hrs_1.result with input as {"normalized_data": {
		"hr_records": [{"employee_id": "E001", "name": "Alice", "status": "active"}],
		"background_checks": [{"employee_id": "E001", "status": "completed"}],
	}}
	result.compliant == true
}

test_missing_check if {
	result := ucf_hrs_1.result with input as {"normalized_data": {
		"hr_records": [{"employee_id": "E001", "name": "Alice", "status": "active"}],
		"background_checks": [],
	}}
	result.compliant == false
}
