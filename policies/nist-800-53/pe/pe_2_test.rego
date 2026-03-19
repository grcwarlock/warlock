package nist.pe.pe_2_test

import rego.v1

import data.nist.pe.pe_2

test_compliant_physical_auth if {
	result := pe_2.result with input as {"normalized_data": {
		"physical_security": {
			"facilities": [{"facility_id": "DC-1", "access_authorization_list_maintained": true, "authorization_list_reviewed_within_90_days": true}],
			"access_holders": [{"person_id": "EMP-001", "authorization_documented": true, "credentials_issued": true}],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unauthorized if {
	result := pe_2.result with input as {"normalized_data": {
		"physical_security": {
			"facilities": [{"facility_id": "DC-1", "access_authorization_list_maintained": false}],
			"access_holders": [{"person_id": "EMP-002", "authorization_documented": false, "credentials_issued": false}],
		},
	}}
	result.compliant == false
}
