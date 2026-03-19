package soc2.cc4_test

import rego.v1

import data.soc2.cc4

test_compliant_monitoring if {
	result := cc4.result with input as {"normalized_data": {"governance": {
		"continuous_monitoring_enabled": true,
		"monitoring_dashboards_configured": true,
		"independent_evaluations_performed": true,
		"deficiency_tracking_enabled": true,
		"deficiencies": [],
		"deficiency_reporting_to_management": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_monitoring if {
	result := cc4.result with input as {"normalized_data": {"governance": {
		"deficiencies": [],
	}}}
	result.compliant == false
}
