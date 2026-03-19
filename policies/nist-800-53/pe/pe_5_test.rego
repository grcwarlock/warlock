package nist.pe.pe_5_test

import rego.v1

import data.nist.pe.pe_5

test_compliant if {
	result := pe_5.result with input as {"normalized_data": {"physical_security": {"output_devices": [{"device_id": "PRN-1", "device_type": "printer", "access_controlled": true, "in_public_area": false, "handles_sensitive_output": false, "shared": true, "requires_authentication_for_pickup": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_5.result with input as {"normalized_data": {"physical_security": {"output_devices": [{"device_id": "PRN-2", "device_type": "printer", "access_controlled": false, "in_public_area": true, "handles_sensitive_output": true, "shared": true, "requires_authentication_for_pickup": false}]}}}
	result.compliant == false
}
