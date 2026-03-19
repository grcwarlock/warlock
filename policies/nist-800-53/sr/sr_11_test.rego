package nist.sr.sr_11_test

import rego.v1

import data.nist.sr.sr_11

test_compliant_authenticity if {
	result := sr_11.result with input as {"normalized_data": {
		"component_authenticity": {
			"anti_counterfeit_procedures": true,
			"authenticity_verification_process": true,
			"software_bill_of_materials": true,
		},
		"system_components": [{"name": "comp1", "requires_authenticity_verification": true, "authenticity_verified": true}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_authenticity if {
	result := sr_11.result with input as {"normalized_data": {}}
	result.compliant == false
}
