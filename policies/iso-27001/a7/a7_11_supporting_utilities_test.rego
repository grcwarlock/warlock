package iso_27001.a7.a7_11_test

import rego.v1

import data.iso_27001.a7.a7_11

test_compliant_a7_11 if {
	result := a7_11.result with input as {"normalized_data": {
		"rds": {
			"instances": [],
		},
		"autoscaling": {
			"groups": ["item1"],
		},
		"ec2": {
			"instance_count": 0,
		},
		"route53": {
			"health_checks": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_11 if {
	result := a7_11.result with input as {"normalized_data": {
		"rds": {"instances": [{"identifier": "db-1", "is_production": true, "multi_az": false}]},
		"autoscaling": {"groups": [{"name": "asg-1", "availability_zones": ["us-east-1a"]}]},
		"ec2": {"instance_count": 2},
		"route53": {"health_checks": []},
	}}
	result.compliant == false
}
