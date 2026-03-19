package hipaa.s164_310.s164_310_a_1_test

import rego.v1

import data.hipaa.s164_310.s164_310_a_1

test_compliant_facility_access if {
	result := s164_310_a_1.result with input as {"normalized_data": {
		"policies": {
			"facility_access_controls": true,
			"facility_security_plan": true,
			"maintenance_records_documented": true,
		},
		"config": {"visitor_access_logging_enabled": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_facility_access_policy if {
	result := s164_310_a_1.result with input as {"normalized_data": {
		"policies": {
			"facility_access_controls": false,
			"facility_security_plan": false,
			"maintenance_records_documented": false,
		},
		"config": {"visitor_access_logging_enabled": false},
	}}
	result.compliant == false
}
