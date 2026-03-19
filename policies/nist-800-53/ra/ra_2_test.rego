package nist.ra.ra_2_test

import rego.v1

import data.nist.ra.ra_2

test_compliant_categorization if {
	result := ra_2.result with input as {"normalized_data": {
		"security_categorization": {
			"approved_by_authorizing_official": true,
			"fips_199_applied": true,
			"last_review_days": 100,
			"impact_levels_defined": true,
		},
		"system_inventory": {"systems": [{"name": "sys1", "security_categorization": "moderate"}]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_categorization if {
	result := ra_2.result with input as {"normalized_data": {}}
	result.compliant == false
}
