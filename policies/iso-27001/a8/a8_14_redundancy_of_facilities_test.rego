package iso_27001.a8.a8_14_test

import rego.v1

import data.iso_27001.a8.a8_14

test_compliant_a8_14 if {
	result := a8_14.result with input as {"normalized_data": {
		"rds": {
			"instances": [],
		},
		"elb": {
			"load_balancers": [],
		},
		"autoscaling": {
			"groups": [],
		},
		"elasticache": {
			"replication_groups": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_14 if {
	result := a8_14.result with input as {"normalized_data": {
		"rds": {"instances": [{"identifier": "db-1", "multi_az": false}]},
		"elb": {"load_balancers": [{"name": "lb-1", "availability_zones": ["us-east-1a"]}]},
		"autoscaling": {"groups": [{"name": "asg-1", "availability_zones": ["us-east-1a"]}]},
		"elasticache": {"replication_groups": []},
	}}
	result.compliant == false
}
