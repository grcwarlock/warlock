package nist.pl.pl_10_test

import rego.v1

import data.nist.pl.pl_10

test_compliant if {
	result := pl_10.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "control_baseline_selected": true, "baseline_level": "moderate", "baseline_selection_justified": true, "fips_199_categorization_completed": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pl_10.result with input as {"normalized_data": {"planning": {"systems": [{"system_id": "sys-1", "control_baseline_selected": false, "fips_199_categorization_completed": false}]}}}
	result.compliant == false
}
