package nist.pm.pm_12_test

import rego.v1

import data.nist.pm.pm_12

test_compliant_insider_threat if {
	result := pm_12.result with input as {"normalized_data": {"insider_threat_program": {
		"threat_indicators_defined": true,
		"awareness_training_provided": true,
		"cross_discipline_team": true,
		"reporting_mechanism": true,
		"last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_program if {
	result := pm_12.result with input as {"normalized_data": {}}
	result.compliant == false
}
