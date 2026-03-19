package nist.sc.sc_7_test

import rego.v1

import data.nist.sc.sc_7

test_compliant if {
	result := sc_7.result with input as {"normalized_data": {"rules": [{"direction": "inbound", "source": "10.0.0.0/8", "port_range": [443, 443], "protocol": "tcp", "group_name": "internal-sg"}], "default_deny_inbound": true}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := sc_7.result with input as {"normalized_data": {"rules": [{"direction": "inbound", "source": "0.0.0.0/0", "port_range": [22, 22], "protocol": "tcp", "group_name": "bad-sg"}], "default_deny_inbound": false}}
	result.compliant == false
}
