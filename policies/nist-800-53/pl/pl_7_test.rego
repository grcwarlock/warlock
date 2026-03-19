package nist.pl.pl_7_test

import rego.v1

import data.nist.pl.pl_7

test_compliant if {
	result := pl_7.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "processes_pii": true, "pia_conducted": true, "pia_reviewed_within_365_days": true, "high_risk_processing": true, "dpia_conducted": true, "pia_publicly_available": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_7.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "processes_pii": true, "pia_conducted": false, "high_risk_processing": true, "dpia_conducted": false}]}}}
	result.compliant == false
}
