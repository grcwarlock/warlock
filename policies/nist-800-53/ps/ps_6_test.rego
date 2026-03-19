package nist.ps.ps_6_test

import rego.v1

import data.nist.ps.ps_6

test_compliant if {
	result := ps_6.result with input as {"normalized_data": {"access_agreement_policy": {"last_review_days": 100}, "users": [{"username": "alice", "requires_access_agreement": true, "access_agreement_signed": true, "agreement_expiration_days": 365, "requires_nda": true, "nda_signed": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_6.result with input as {"normalized_data": {"users": [{"username": "bob", "requires_access_agreement": true, "access_agreement_signed": false, "requires_nda": true, "nda_signed": false}]}}
	result.compliant == false
}
