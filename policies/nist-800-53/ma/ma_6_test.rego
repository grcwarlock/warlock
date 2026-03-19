package nist.ma.ma_6_test

import rego.v1

import data.nist.ma.ma_6

test_compliant_timely_maintenance if {
	result := ma_6.result with input as {"normalized_data": {
		"maintenance": {
			"systems": [
				{"system_id": "srv-01", "maintenance_overdue": false, "days_overdue": 0, "critical": true, "spare_parts_available": true, "sla_defined": true, "mttr_tracked": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_sla_exceeded if {
	result := ma_6.result with input as {"normalized_data": {
		"maintenance": {
			"systems": [
				{"system_id": "srv-02", "maintenance_overdue": true, "days_overdue": 30, "critical": true, "spare_parts_available": false, "sla_defined": false, "mttr_tracked": false},
			],
		},
	}}
	result.compliant == false
}
