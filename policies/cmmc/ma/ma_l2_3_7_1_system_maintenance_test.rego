package cmmc.ma.ma_l2_3_7_1_test

import rego.v1

import data.cmmc.ma.ma_l2_3_7_1

test_compliant_system_maintenance if {
	result := ma_l2_3_7_1.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "maintenance_schedule_documented": true, "days_since_last_maintenance": 30, "maintenance_activities_logged": true},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_overdue_maintenance if {
	result := ma_l2_3_7_1.result with input as {"normalized_data": {"systems": [
		{"name": "prod-web", "maintenance_schedule_documented": true, "days_since_last_maintenance": 120, "maintenance_activities_logged": true},
	]}}
	result.compliant == false
}
