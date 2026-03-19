package nist.pm.pm_13_test

import rego.v1

import data.nist.pm.pm_13

test_compliant_workforce if {
	result := pm_13.result with input as {"normalized_data": {"security_workforce": {
		"training_requirements_defined": true,
		"skills_assessment_completed": true,
		"last_review_days": 100,
		"personnel": [{"name": "staff1", "role": "security", "certifications_current": true}],
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_workforce if {
	result := pm_13.result with input as {"normalized_data": {}}
	result.compliant == false
}
