package nist.sa.sa_4_test

import rego.v1

import data.nist.sa.sa_4

test_compliant_acquisition if {
	result := sa_4.result with input as {"normalized_data": {
		"acquisition_security_requirements": true,
		"acquisition_contracts": [{
			"id": "C1",
			"security_requirements_included": true,
			"strength_of_mechanism_specified": true,
			"assurance_requirements_specified": true,
			"documentation_requirements_specified": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_requirements if {
	result := sa_4.result with input as {"normalized_data": {}}
	result.compliant == false
}
