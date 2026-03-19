package nist.pm.pm_2_test

import rego.v1

import data.nist.pm.pm_2

test_compliant_leadership if {
	result := pm_2.result with input as {"normalized_data": {
		"senior_agency_official": true,
		"chief_information_security_officer": {
			"has_authority_documented": true,
			"reports_to_head_of_agency": true,
		},
		"security_team": true,
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ciso if {
	result := pm_2.result with input as {"normalized_data": {
		"senior_agency_official": true,
		"security_team": true,
	}}
	result.compliant == false
}
