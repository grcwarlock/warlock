package nist.sa.sa_15_test

import rego.v1

import data.nist.sa.sa_15

test_compliant_dev_process if {
	result := sa_15.result with input as {"normalized_data": {"development_process": {
		"coding_standards_defined": true,
		"approved_tools_list": true,
		"last_review_days": 100,
		"quality_metrics_defined": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_dev_process if {
	result := sa_15.result with input as {"normalized_data": {}}
	result.compliant == false
}
