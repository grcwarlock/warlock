package nist.pt.pt_8_test

import rego.v1

import data.nist.pt.pt_8

test_compliant if {
	result := pt_8.result with input as {"normalized_data": {"computer_matching": {"matching_agreements_established": true, "agreements": [{"name": "MA-1", "approved_by_data_integrity_board": true, "expiration_days": 365}], "due_process_protections": true, "independent_verification": true}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
