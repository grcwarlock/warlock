package cmmc.pe.pe_l2_3_10_1_test

import rego.v1

import data.cmmc.pe.pe_l2_3_10_1

test_compliant_physical_access if {
	result := pe_l2_3_10_1.result with input as {"normalized_data": {"facilities": [
		{"name": "hq-datacenter", "physical_access_controls_implemented": true, "visitor_log_maintained": true, "last_access_list_review_days": 30},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_physical_access_controls if {
	result := pe_l2_3_10_1.result with input as {"normalized_data": {"facilities": [
		{"name": "hq-datacenter", "physical_access_controls_implemented": false, "visitor_log_maintained": false, "last_access_list_review_days": 0},
	]}}
	result.compliant == false
}
