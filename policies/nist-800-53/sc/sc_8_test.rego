package nist.sc.sc_8_test

import rego.v1

import data.nist.sc.sc_8

test_compliant if {
	result := sc_8.result with input as {"normalized_data": {"rules": [{"direction": "inbound", "source": "10.0.0.0/8", "port_range": [443, 443], "group_name": "tls-sg"}], "tls_config": {"minimum_tls_version": "1.2"}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := sc_8.result with input as {"normalized_data": {"rules": [{"direction": "inbound", "source": "0.0.0.0/0", "port_range": [80, 80], "group_name": "http-sg"}], "tls_config": {"minimum_tls_version": "1.0"}}}
	result.compliant == false
}
