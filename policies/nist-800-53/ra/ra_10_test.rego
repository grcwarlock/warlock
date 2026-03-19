package nist.ra.ra_10_test

import rego.v1

import data.nist.ra.ra_10

test_compliant_threat_hunting if {
	result := ra_10.result with input as {"normalized_data": {"threat_hunting": {
		"dedicated_team": true,
		"threat_intelligence_feeds": true,
		"last_hunt_days": 30,
		"methodology_defined": true,
		"findings": [{"id": "TH1", "actioned": true}],
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_hunting if {
	result := ra_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
