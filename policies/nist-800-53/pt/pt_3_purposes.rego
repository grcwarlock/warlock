package nist.pt.pt_3

import rego.v1

# PT-3: Personally Identifiable Information Processing Purposes

deny_no_purpose_specification contains msg if {
	not input.normalized_data.pii_processing_purposes
	msg := "PT-3: PII processing purposes have not been specified"
}

deny_purpose_not_documented contains msg if {
	some system in input.normalized_data.systems_processing_pii
	not system.processing_purposes_documented
	msg := sprintf("PT-3: PII processing purposes not documented for system '%s'", [system.name])
}

deny_purpose_exceeds_authority contains msg if {
	some system in input.normalized_data.systems_processing_pii
	system.processing_exceeds_stated_purpose
	msg := sprintf("PT-3: System '%s' processes PII beyond stated purposes", [system.name])
}

deny_purposes_not_reviewed contains msg if {
	pp := input.normalized_data.pii_processing_purposes
	pp.last_review_days > 365
	msg := sprintf("PT-3: PII processing purposes have not been reviewed in %d days", [pp.last_review_days])
}

deny_no_purpose_communication contains msg if {
	pp := input.normalized_data.pii_processing_purposes
	not pp.communicated_to_individuals
	msg := "PT-3: PII processing purposes have not been communicated to individuals"
}

default compliant := false

compliant if {
	count(deny_no_purpose_specification) == 0
	count(deny_purpose_not_documented) == 0
	count(deny_purpose_exceeds_authority) == 0
	count(deny_purposes_not_reviewed) == 0
	count(deny_no_purpose_communication) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_purpose_specification],
		[f | some f in deny_purpose_not_documented],
	),
	array.concat(
		[f | some f in deny_purpose_exceeds_authority],
		array.concat(
			[f | some f in deny_purposes_not_reviewed],
			[f | some f in deny_no_purpose_communication],
		),
	),
)

result := {
	"control_id": "PT-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
