package pci_dss.r10_test

import rego.v1

import data.pci_dss.r10

test_compliant_logging if {
	result := r10.result with input as {"normalized_data": {"audit_logging": {
		"enabled": true,
		"automated_review": true,
		"retention_days": 365,
	}}}
	result.compliant == true
}

test_noncompliant_no_logging if {
	result := r10.result with input as {"normalized_data": {"audit_logging": {
		"enabled": false,
		"automated_review": false,
		"retention_days": 0,
	}}}
	result.compliant == false
}

test_noncompliant_short_retention if {
	result := r10.result with input as {"normalized_data": {"audit_logging": {
		"enabled": true,
		"automated_review": true,
		"retention_days": 90,
	}}}
	result.compliant == false
}
