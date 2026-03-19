package nist.pt.pt_6_test

import rego.v1

import data.nist.pt.pt_6

test_compliant if {
	result := pt_6.result with input as {"normalized_data": {"system_of_records_notices": {"notices": [{"system_name": "HR-DB", "last_review_days": 365, "includes_routine_uses": true, "published_in_federal_register": true}]}, "systems_processing_pii": [{"name": "HR-DB", "is_system_of_records": true, "sorn_published": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_6.result with input as {"normalized_data": {"systems_processing_pii": [{"name": "HR-DB", "is_system_of_records": true, "sorn_published": false}]}}
	result.compliant == false
}
