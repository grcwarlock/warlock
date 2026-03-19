package nist.pt.pt_2

import rego.v1

# PT-2: Authority to Process Personally Identifiable Information

deny_no_authority_documented contains msg if {
	not input.normalized_data.pii_processing_authority
	msg := "PT-2: No authority to process PII documented"
}

deny_no_legal_basis contains msg if {
	auth := input.normalized_data.pii_processing_authority
	not auth.legal_basis_identified
	msg := "PT-2: Legal basis for PII processing has not been identified"
}

deny_processing_without_authority contains msg if {
	some system in input.normalized_data.systems_processing_pii
	not system.processing_authority_documented
	msg := sprintf("PT-2: System '%s' processes PII without documented authority", [system.name])
}

deny_authority_not_reviewed contains msg if {
	auth := input.normalized_data.pii_processing_authority
	auth.last_review_days > 365
	msg := sprintf("PT-2: Authority to process PII has not been reviewed in %d days", [auth.last_review_days])
}

deny_no_purpose_limitation contains msg if {
	some system in input.normalized_data.systems_processing_pii
	not system.purpose_limitation_enforced
	msg := sprintf("PT-2: System '%s' does not enforce purpose limitation for PII processing", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_authority_documented) == 0
	count(deny_no_legal_basis) == 0
	count(deny_processing_without_authority) == 0
	count(deny_authority_not_reviewed) == 0
	count(deny_no_purpose_limitation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_authority_documented],
		[f | some f in deny_no_legal_basis],
	),
	array.concat(
		[f | some f in deny_processing_without_authority],
		array.concat(
			[f | some f in deny_authority_not_reviewed],
			[f | some f in deny_no_purpose_limitation],
		),
	),
)

result := {
	"control_id": "PT-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
