package pci_dss.r12_test

import rego.v1

import data.pci_dss.r12

test_compliant_policy if {
	result := r12.result with input as {"normalized_data": {
		"policies": [{"name": "InfoSec Policy", "days_since_review": 30}],
		"training": {"completion_rate": 98},
		"incident_response": {"plan_tested": true},
	}}
	result.compliant == true
}

test_noncompliant_stale_policy if {
	result := r12.result with input as {"normalized_data": {
		"policies": [{"name": "InfoSec Policy", "days_since_review": 400}],
		"training": {"completion_rate": 98},
		"incident_response": {"plan_tested": true},
	}}
	result.compliant == false
}

test_noncompliant_low_training if {
	result := r12.result with input as {"normalized_data": {
		"policies": [{"name": "InfoSec Policy", "days_since_review": 30}],
		"training": {"completion_rate": 80},
		"incident_response": {"plan_tested": true},
	}}
	result.compliant == false
}
