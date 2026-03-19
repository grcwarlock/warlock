package nist.pt.pt_3_test

import rego.v1

import data.nist.pt.pt_3

test_compliant if {
	result := pt_3.result with input as {"normalized_data": {"pii_processing_purposes": {"last_review_days": 100, "communicated_to_individuals": true}, "systems_processing_pii": [{"name": "CRM", "processing_purposes_documented": true, "processing_exceeds_stated_purpose": false}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_3.result with input as {"normalized_data": {"systems_processing_pii": [{"name": "CRM", "processing_purposes_documented": false, "processing_exceeds_stated_purpose": true}]}}
	result.compliant == false
}
