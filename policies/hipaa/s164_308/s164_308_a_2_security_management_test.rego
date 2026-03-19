package hipaa.s164_308.s164_308_a_2_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_2

test_compliant_security_management if {
	result := s164_308_a_2.result with input as {"normalized_data": {"organization": {
		"security_officer_assigned": true,
		"security_officer_contact_documented": true,
		"security_responsibilities_documented": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_security_officer if {
	result := s164_308_a_2.result with input as {"normalized_data": {"organization": {
		"security_officer_assigned": false,
		"security_officer_contact_documented": false,
		"security_responsibilities_documented": false,
	}}}
	result.compliant == false
}
