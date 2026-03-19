package soc2.p1_test

import rego.v1

import data.soc2.p1

test_compliant_privacy if {
	result := p1.result with input as {"normalized_data": {"privacy": {
		"privacy_policy_published": true,
		"consent_mechanisms_implemented": true,
		"personal_data_inventory_exists": true,
		"purpose_limitation_enforced": true,
		"dsar_process_exists": true,
		"disclosure_controls_exist": true,
		"data_quality_procedures_exist": true,
		"privacy_monitoring_enabled": true,
		"privacy_impact_assessments_performed": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_privacy_policy if {
	result := p1.result with input as {"normalized_data": {"privacy": {}}}
	result.compliant == false
}
