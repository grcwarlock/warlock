package iso_27001.a8.a8_21_test

import rego.v1

import data.iso_27001.a8.a8_21

test_compliant_a8_21 if {
	result := a8_21.result with input as {"normalized_data": {
		"elb": {
			"load_balancers": [],
		},
		"cloudfront": {
			"distributions": [],
		},
		"apigateway": {
			"apis": [],
		},
		"waf": {
			"web_acls": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_21 if {
	result := a8_21.result with input as {"normalized_data": {
		"elb": {"load_balancers": [{"name": "lb-1", "has_https_listener": false}]},
		"waf": {"web_acls": []},
		"cloudfront": {"distributions": []},
		"apigateway": {"apis": []},
	}}
	result.compliant == false
}
