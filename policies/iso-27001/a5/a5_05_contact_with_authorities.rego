package iso_27001.a5.a5_05

import rego.v1

# A.5.5: Contact with Authorities
# Validates contacts with regulatory authorities are documented and accessible

deny_no_security_contact contains msg if {
	not input.normalized_data.account.security_contact_configured
	msg := "A.5.5: No security alternate contact is configured for the account"
}

deny_no_operations_contact contains msg if {
	not input.normalized_data.account.operations_contact_configured
	msg := "A.5.5: No operations alternate contact is configured for the account"
}

deny_no_authority_contacts_documented contains msg if {
	not input.normalized_data.policies.authority_contacts_documented
	msg := "A.5.5: Regulatory authority contacts are not documented or accessible"
}

deny_no_incident_notification_channel contains msg if {
	not input.normalized_data.sns.security_notification_topic_exists
	msg := "A.5.5: No SNS topic exists for security incident notification to authorities"
}

default compliant := false

compliant if {
	count(deny_no_security_contact) == 0
	count(deny_no_operations_contact) == 0
	count(deny_no_authority_contacts_documented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_contact],
		[f | some f in deny_no_operations_contact],
	),
	array.concat(
		[f | some f in deny_no_authority_contacts_documented],
		[f | some f in deny_no_incident_notification_channel],
	),
)

result := {
	"control_id": "A.5.5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
