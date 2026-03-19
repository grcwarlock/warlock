package nist.sr.sr_8_test

import rego.v1

import data.nist.sr.sr_8

test_compliant_notifications if {
	result := sr_8.result with input as {"normalized_data": {
		"supplier_notification_agreements": {"last_review_days": 100},
		"suppliers": [{
			"name": "sup1",
			"is_critical": true,
			"notification_agreement_signed": true,
			"breach_notification_included": true,
			"vulnerability_notification_included": true,
		}],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_agreements if {
	result := sr_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
