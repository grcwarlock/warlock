package nist.pm.pm_6_test

import rego.v1

import data.nist.pm.pm_6

test_compliant_metrics if {
	result := pm_6.result with input as {"normalized_data": {"security_metrics": {
		"key_performance_indicators": ["kpi1"],
		"reported_to_leadership": true,
		"last_report_days": 30,
		"baseline_established": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_metrics if {
	result := pm_6.result with input as {"normalized_data": {}}
	result.compliant == false
}
