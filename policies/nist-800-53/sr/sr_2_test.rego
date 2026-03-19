package nist.sr.sr_2_test

import rego.v1

import data.nist.sr.sr_2

test_compliant_scrm_plan if {
	result := sr_2.result with input as {"normalized_data": {"supply_chain_risk_plan": {
		"approved": true,
		"last_review_days": 100,
		"risks_identified": true,
		"mitigation_strategies_defined": true,
		"integrated_with_enterprise_risk": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_plan if {
	result := sr_2.result with input as {"normalized_data": {}}
	result.compliant == false
}
