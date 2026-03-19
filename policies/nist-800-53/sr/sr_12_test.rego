package nist.sr.sr_12_test

import rego.v1

import data.nist.sr.sr_12

test_compliant_disposal if {
	result := sr_12.result with input as {"normalized_data": {
		"component_disposal": {
			"sanitization_procedures": true,
			"disposal_records_maintained": true,
		},
		"disposed_components": [{"name": "comp1", "data_sanitized": true, "disposal_verified": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_disposal if {
	result := sr_12.result with input as {"normalized_data": {}}
	result.compliant == false
}
