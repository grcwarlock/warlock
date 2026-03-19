package nist.pt.pt_4

import rego.v1

# PT-4: Consent

deny_no_consent_mechanism contains msg if {
	not input.normalized_data.pii_consent
	msg := "PT-4: No consent mechanism established for PII processing"
}

deny_consent_not_obtained contains msg if {
	some system in input.normalized_data.systems_processing_pii
	system.requires_consent
	not system.consent_obtained
	msg := sprintf("PT-4: System '%s' processes PII without obtaining required consent", [system.name])
}

deny_no_consent_records contains msg if {
	consent := input.normalized_data.pii_consent
	not consent.records_maintained
	msg := "PT-4: No records maintained of consent obtained for PII processing"
}

deny_no_consent_withdrawal contains msg if {
	consent := input.normalized_data.pii_consent
	not consent.withdrawal_mechanism
	msg := "PT-4: No mechanism for individuals to withdraw consent for PII processing"
}

deny_consent_not_granular contains msg if {
	consent := input.normalized_data.pii_consent
	not consent.granular_consent
	msg := "PT-4: Consent mechanism does not provide granular choices for PII processing activities"
}

default compliant := false

compliant if {
	count(deny_no_consent_mechanism) == 0
	count(deny_consent_not_obtained) == 0
	count(deny_no_consent_records) == 0
	count(deny_no_consent_withdrawal) == 0
	count(deny_consent_not_granular) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_consent_mechanism],
		[f | some f in deny_consent_not_obtained],
	),
	array.concat(
		[f | some f in deny_no_consent_records],
		array.concat(
			[f | some f in deny_no_consent_withdrawal],
			[f | some f in deny_consent_not_granular],
		),
	),
)

result := {
	"control_id": "PT-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
