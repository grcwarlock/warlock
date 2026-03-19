package nist.ps.ps_4_test

import rego.v1

import data.nist.ps.ps_4

test_compliant if {
	result := ps_4.result with input as {"normalized_data": {"termination_process": true, "terminated_personnel": [{"name": "Alice", "access_revoked": true, "credentials_revoked": true, "exit_interview_completed": true, "property_returned": true, "hours_to_revoke": 2}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_4.result with input as {"normalized_data": {"termination_process": true, "terminated_personnel": [{"name": "Bob", "access_revoked": false, "credentials_revoked": false, "exit_interview_completed": false, "property_returned": false, "hours_to_revoke": 48}]}}
	result.compliant == false
}
