package nist.ps.ps_7_test

import rego.v1

import data.nist.ps.ps_7

test_compliant if {
	result := ps_7.result with input as {"normalized_data": {"external_personnel_policy": {"compliance_monitoring": true}, "external_personnel": [{"name": "Vendor A", "organization": "Acme", "security_agreement_signed": true, "requires_screening": true, "screening_completed": true, "has_system_access": true, "access_monitored": true}], "external_contracts": [{"id": "C-001", "security_requirements_included": true}]}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := ps_7.result with input as {"normalized_data": {"external_personnel": [{"name": "Vendor B", "organization": "BadCo", "security_agreement_signed": false, "requires_screening": true, "screening_completed": false, "has_system_access": true, "access_monitored": false}], "external_contracts": [{"id": "C-002", "security_requirements_included": false}]}}
	result.compliant == false
}
