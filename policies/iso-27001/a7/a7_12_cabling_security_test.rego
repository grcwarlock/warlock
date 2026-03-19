package iso_27001.a7.a7_12_test

import rego.v1

import data.iso_27001.a7.a7_12

test_compliant_a7_12 if {
	result := a7_12.result with input as {"normalized_data": {
		"vpn": {
			"connections": [],
		},
		"elb": {
			"listeners": [],
		},
		"directconnect": {
			"connections": [],
		},
		"vpc_endpoints": ["item1"],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_12 if {
	result := a7_12.result with input as {"normalized_data": {
		"vpn": {"connections": [{"id": "vpn-123", "state": "available", "encrypted": false}]},
		"elb": {"listeners": []},
		"directconnect": {"connections": []},
		"vpc_endpoints": [],
	}}
	result.compliant == false
}
