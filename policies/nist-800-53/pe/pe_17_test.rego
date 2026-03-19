package nist.pe.pe_17_test

import rego.v1

import data.nist.pe.pe_17

test_compliant if {
	result := pe_17.result with input as {"normalized_data": {"physical_security": {"alternate_work_site_policy_defined": true, "alternate_work_sites": [{"site_id": "AWS-1", "security_controls_implemented": true, "vpn_required": true, "security_assessment_completed": true, "secure_communication_channels": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_17.result with input as {"normalized_data": {"physical_security": {"alternate_work_sites": [{"site_id": "AWS-2", "security_controls_implemented": false, "vpn_required": false, "security_assessment_completed": false, "secure_communication_channels": false}]}}}
	result.compliant == false
}
