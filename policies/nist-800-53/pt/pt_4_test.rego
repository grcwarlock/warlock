package nist.pt.pt_4_test

import rego.v1

import data.nist.pt.pt_4

test_compliant if {
	result := pt_4.result with input as {"normalized_data": {"pii_consent": {"records_maintained": true, "withdrawal_mechanism": true, "granular_consent": true}, "systems_processing_pii": [{"name": "App", "requires_consent": true, "consent_obtained": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_4.result with input as {"normalized_data": {"systems_processing_pii": [{"name": "App", "requires_consent": true, "consent_obtained": false}]}}
	result.compliant == false
}
