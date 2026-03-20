package gdpr.art28_test

import rego.v1

import data.gdpr.art28

test_compliant_processor if {
	result := art28.result with input as {"normalized_data": {
		"processors": [{"name": "Vendor A", "dpa_signed": true, "days_since_access_review": 30}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_dpa if {
	result := art28.result with input as {"normalized_data": {
		"processors": [{"name": "Vendor B", "dpa_signed": false, "days_since_access_review": 10}],
	}}
	result.compliant == false
}

test_overdue_access_review if {
	result := art28.result with input as {"normalized_data": {
		"processors": [{"name": "Vendor C", "dpa_signed": true, "days_since_access_review": 120}],
	}}
	result.compliant == false
}
