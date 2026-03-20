package pci_dss.r7_test

import rego.v1

import data.pci_dss.r7

test_compliant_access if {
	result := r7.result with input as {"normalized_data": {
		"users": [{"username": "user1", "policies": [{"name": "ReadOnly", "effect": "Allow", "action": "s3:Get*", "resource": "arn:aws:s3:::data/*"}]}],
		"access_review": {"name": "Q1-2026", "overdue": false},
	}}
	result.compliant == true
}

test_noncompliant_excessive if {
	result := r7.result with input as {"normalized_data": {
		"users": [{"username": "dev1", "policies": [{"name": "Admin", "effect": "Allow", "action": "*", "resource": "*"}]}],
		"access_review": {"name": "Q1-2026", "overdue": false},
	}}
	result.compliant == false
}
