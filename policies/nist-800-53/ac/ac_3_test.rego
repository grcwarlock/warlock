package nist.ac.ac_3_test

import rego.v1

import data.nist.ac.ac_3

test_compliant_no_public_access if {
	result := ac_3.result with input as {"normalized_data": {
		"rules": [
			{"direction": "inbound", "source": "10.0.0.0/8", "port_range": [22, 22], "protocol": "tcp", "group_name": "internal-sg"},
		],
		"default_deny_inbound": true,
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_public_ssh if {
	result := ac_3.result with input as {"normalized_data": {
		"rules": [
			{"direction": "inbound", "source": "0.0.0.0/0", "port_range": [22, 22], "protocol": "tcp", "group_name": "bad-sg"},
		],
		"default_deny_inbound": true,
	}}
	result.compliant == false
}
