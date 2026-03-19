package nist.sr.sr_5_test

import rego.v1

import data.nist.sr.sr_5

test_compliant_acquisition if {
	result := sr_5.result with input as {"normalized_data": {"supply_chain_acquisition": {
		"approved_vendor_list": true,
		"security_requirements_in_acquisitions": true,
		"last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_strategies if {
	result := sr_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
