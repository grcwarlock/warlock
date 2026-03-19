package iso_27001.a8.a8_20_test

import rego.v1

import data.iso_27001.a8.a8_20

test_compliant_a8_20 if {
	result := a8_20.result with input as {"normalized_data": {
		"config": {
			"restricted_ssh_rule_exists": true,
		},
		"rules": [],
		"vpcs": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_20 if {
	result := a8_20.result with input as {"normalized_data": {
		"rules": [{"direction": "inbound", "source": "0.0.0.0/0", "protocol": "all", "group_name": "bad-sg", "port_range": [22, 22]}],
		"vpcs": [{"id": "vpc-123", "flow_logs_enabled": false}],
		"config": {"restricted_ssh_rule_exists": false},
	}}
	result.compliant == false
}
