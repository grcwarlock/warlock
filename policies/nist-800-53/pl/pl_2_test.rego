package nist.pl.pl_2_test

import rego.v1

import data.nist.pl.pl_2

test_compliant if {
	result := pl_2.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "security_plan_exists": true, "security_plan_reviewed_within_365_days": true, "ssp_defines_authorization_boundary": true, "ssp_documents_controls": true, "ssp_approved_by_authorizing_official": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_2.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "security_plan_exists": false}]}}}
	result.compliant == false
}
