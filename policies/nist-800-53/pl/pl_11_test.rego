package nist.pl.pl_11_test

import rego.v1

import data.nist.pl.pl_11

test_compliant if {
	result := pl_11.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "control_baseline_selected": true, "baseline_tailored": true, "tailoring_documented": true, "tailoring_justified": true, "tailoring_approved_by_authorizing_official": true, "has_compensating_controls": false}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_11.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "control_baseline_selected": true, "baseline_tailored": false}]}}}
	result.compliant == false
}
