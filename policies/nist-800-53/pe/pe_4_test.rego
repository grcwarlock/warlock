package nist.pe.pe_4_test

import rego.v1

import data.nist.pe.pe_4

test_compliant if {
	result := pe_4.result with input as {"normalized_data": {"physical_security": {"transmission_media_inventory_maintained": true, "transmission_media": [{"media_id": "CAB-1", "media_type": "fiber", "physically_protected": true, "carries_sensitive_data": true, "in_secured_conduit": true, "distribution_frame_accessible": false, "distribution_frame_locked": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_4.result with input as {"normalized_data": {"physical_security": {"transmission_media_inventory_maintained": false, "transmission_media": [{"media_id": "CAB-2", "media_type": "copper", "physically_protected": false, "carries_sensitive_data": true, "in_secured_conduit": false, "distribution_frame_accessible": true, "distribution_frame_locked": false}]}}}
	result.compliant == false
}
