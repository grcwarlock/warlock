package iso_27001.a7.a7_08_test

import rego.v1

import data.iso_27001.a7.a7_08

test_compliant_a7_08 if {
	result := a7_08.result with input as {"normalized_data": {
		"ec2": {
			"dedicated_hosts_configured": true,
			"instances": [],
			"instance_count": 5,
			"placement_groups": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_08 if {
	result := a7_08.result with input as {"normalized_data": {
		"ec2": {
			"instances": [{"id": "i-123", "region": "us-west-2", "is_nitro_based": false, "is_production": true}],
			"dedicated_hosts_configured": false,
			"instance_count": 5,
			"placement_groups": [],
		},
		"organization": {"approved_regions": ["us-east-1"]},
		"compliance": {"requires_dedicated_hosts": true},
	}}
	result.compliant == false
}
