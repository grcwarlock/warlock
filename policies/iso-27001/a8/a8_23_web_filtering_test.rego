package iso_27001.a8.a8_23_test

import rego.v1

import data.iso_27001.a8.a8_23

test_compliant_a8_23 if {
	result := a8_23.result with input as {"normalized_data": {
		"network_firewall": {
			"deployed": true,
			"rule_groups": ["item1"],
		},
		"route53resolver": {
			"dns_firewall_configured": true,
			"dns_firewall_associated_to_vpc": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_23 if {
	result := a8_23.result with input as {"normalized_data": {}}
	result.compliant == false
}
