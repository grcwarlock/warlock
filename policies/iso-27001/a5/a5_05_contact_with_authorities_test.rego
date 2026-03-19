package iso_27001.a5.a5_05_test

import rego.v1

import data.iso_27001.a5.a5_05

test_compliant_a5_05 if {
	result := a5_05.result with input as {"normalized_data": {
		"account": {
			"security_contact_configured": true,
			"operations_contact_configured": true,
		},
		"policies": {
			"authority_contacts_documented": true,
		},
		"sns": {
			"security_notification_topic_exists": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_05 if {
	result := a5_05.result with input as {"normalized_data": {}}
	result.compliant == false
}
