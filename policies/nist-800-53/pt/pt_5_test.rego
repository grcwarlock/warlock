package nist.pt.pt_5_test

import rego.v1

import data.nist.pt.pt_5

test_compliant if {
	result := pt_5.result with input as {"normalized_data": {"privacy_notice": {"last_update_days": 100, "includes_purpose_of_processing": true, "includes_pii_categories": true, "includes_individual_rights": true, "publicly_accessible": true}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pt_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
