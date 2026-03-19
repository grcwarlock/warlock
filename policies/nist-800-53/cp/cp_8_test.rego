package nist.cp.cp_8_test

import rego.v1

import data.nist.cp.cp_8

test_compliant_telecom if {
	result := cp_8.result with input as {"normalized_data": {
		"telecommunications": {
			"provider_count": 2,
			"diverse_routing_enabled": true,
			"vpn_configured": true,
			"vpn_redundancy": true,
			"service_agreement_documented": true,
			"bandwidth_sufficient": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_telecom if {
	result := cp_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
