package warlock.iso_27701.consent

import rego.v1

# ISO 27701 Consent Management Controls
# 7.2.3, 7.2.4, 7.2.5: Consent obtaining, recording, and withdrawal

# 7.2.3: Consent obtained for PII processing
deny_no_consent_mechanism contains msg if {
	not input.normalized_data.privacy.consent_mechanism_active
	msg := "7.2.3: No active consent mechanism — PII may be processed without lawful basis"
}

# 7.2.4: Records of consent maintained
deny_no_consent_records contains msg if {
	not input.normalized_data.privacy.consent_records_maintained
	msg := "7.2.4: Consent records not maintained — cannot demonstrate lawful processing"
}

# 7.2.5: Consent withdrawal mechanism
deny_no_withdrawal_mechanism contains msg if {
	input.normalized_data.privacy.consent_mechanism_active
	not input.normalized_data.privacy.consent_withdrawal_available
	msg := "7.2.5: No consent withdrawal mechanism — data subjects cannot revoke consent"
}

# 7.2.2: Identify lawful basis — processing has documented legal basis
deny_no_lawful_basis contains msg if {
	some processing in input.normalized_data.privacy.processing_activities
	not processing.lawful_basis_documented
	msg := sprintf("7.2.2: Processing activity '%s' has no documented lawful basis", [processing.name])
}

# 7.2.8: Records of processing activities
deny_no_processing_records contains msg if {
	not input.normalized_data.privacy.processing_records_maintained
	msg := "7.2.8: No records of processing activities maintained"
}

default compliant := false

compliant if {
	count(deny_no_consent_mechanism) == 0
	count(deny_no_consent_records) == 0
	count(deny_no_withdrawal_mechanism) == 0
	count(deny_no_lawful_basis) == 0
	count(deny_no_processing_records) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_consent_mechanism],
		[f | some f in deny_no_consent_records],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_withdrawal_mechanism],
			[f | some f in deny_no_lawful_basis],
		),
		[f | some f in deny_no_processing_records],
	),
)

result := {
	"control_id": "7.2",
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
