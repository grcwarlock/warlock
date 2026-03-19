package nist.sr.sr_10_test

import rego.v1

import data.nist.sr.sr_10

test_compliant_inspection if {
	result := sr_10.result with input as {"normalized_data": {
		"system_inspection": {"schedule_defined": true, "random_inspections_conducted": true},
		"delivered_components": [{"name": "comp1", "inspection_completed": true}],
		"inspection_findings": [{"id": "IF1", "status": "closed", "days_open": 0}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_inspection if {
	result := sr_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
