package nist.pt.pt_2_test

import rego.v1

import data.nist.pt.pt_2

test_compliant if {
	result := pt_2.result with input as {"normalized_data": {"pii_processing_authority": {"legal_basis_identified": true, "last_review_days": 100}, "systems_processing_pii": [{"name": "HR-System", "processing_authority_documented": true, "purpose_limitation_enforced": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_2.result with input as {"normalized_data": {"systems_processing_pii": [{"name": "HR-System", "processing_authority_documented": false, "purpose_limitation_enforced": false}]}}
	result.compliant == false
}
