package pci_dss.r1_test

import rego.v1

import data.pci_dss.r1

test_compliant_network if {
	result := r1.result with input as {"normalized_data": {"security_groups": [
		{"id": "sg-123", "inbound_rules": [{"cidr": "10.0.0.0/8", "port": 443, "protocol": "tcp"}]},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_open_port if {
	result := r1.result with input as {"normalized_data": {"security_groups": [
		{"id": "sg-123", "inbound_rules": [{"cidr": "0.0.0.0/0", "port": 22, "protocol": "tcp"}]},
	]}}
	result.compliant == false
}

test_noncompliant_no_firewalls if {
	result := r1.result with input as {"normalized_data": {"security_groups": []}}
	result.compliant == false
}

test_noncompliant_all_traffic if {
	result := r1.result with input as {"normalized_data": {"security_groups": [
		{"id": "sg-123", "inbound_rules": [{"cidr": "0.0.0.0/0", "port": 0, "protocol": "-1"}]},
	]}}
	result.compliant == false
}
