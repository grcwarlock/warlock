package nist.pe.pe_18_test

import rego.v1

import data.nist.pe.pe_18

test_compliant if {
	result := pe_18.result with input as {"normalized_data": {"physical_security": {"system_components": [{"component_id": "SRV-1", "component_type": "server", "in_public_area": false, "processes_sensitive_data": true, "critical": true, "physically_separated": true, "display_visible_to_unauthorized": false, "location_documented": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_18.result with input as {"normalized_data": {"physical_security": {"system_components": [{"component_id": "SRV-2", "component_type": "server", "in_public_area": true, "processes_sensitive_data": true, "critical": true, "physically_separated": false, "display_visible_to_unauthorized": true, "location_documented": false}]}}}
	result.compliant == false
}
