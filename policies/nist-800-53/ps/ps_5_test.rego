package nist.ps.ps_5_test

import rego.v1

import data.nist.ps.ps_5

test_compliant if {
	result := ps_5.result with input as {"normalized_data": {"transfer_process": true, "transferred_personnel": [{"name": "Alice", "access_reviewed_on_transfer": true, "access_modification_needed": false, "days_to_process": 2, "security_notified": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_5.result with input as {"normalized_data": {"transferred_personnel": [{"name": "Bob", "access_reviewed_on_transfer": false, "days_to_process": 10, "security_notified": false}]}}
	result.compliant == false
}
