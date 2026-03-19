package nist.sa.sa_16_test

import rego.v1

import data.nist.sa.sa_16

test_compliant_dev_training if {
	result := sa_16.result with input as {"normalized_data": {
		"developer_training": {
			"last_update_days": 100,
			"covers_secure_coding": true,
		},
		"developers": [{"name": "dev1", "security_training_completed": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_training if {
	result := sa_16.result with input as {"normalized_data": {}}
	result.compliant == false
}
