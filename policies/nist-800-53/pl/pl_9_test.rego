package nist.pl.pl_9_test

import rego.v1

import data.nist.pl.pl_9

test_compliant if {
	result := pl_9.result with input as {"normalized_data": {"planning": {"centralized_management_established": true, "security_controls": [{"control_id": "AC-2", "requires_central_management": true, "centrally_managed": true}], "central_policy_repository": true, "centralized_monitoring": true}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_9.result with input as {"normalized_data": {"planning": {"security_controls": [], "central_policy_repository": false, "centralized_monitoring": false}}}
	result.compliant == false
}
