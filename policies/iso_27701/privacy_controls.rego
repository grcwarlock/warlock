package warlock.iso_27701

import rego.v1

# ISO 27701 Privacy Information Management
# Controls for PII processing, consent, and data subject rights

# 7.2.1: Purpose limitation — PII processed only for identified purposes
deny_no_purpose_limitation contains msg if {
	not input.normalized_data.privacy.purpose_limitation_policy
	msg := "7.2.1: No purpose limitation policy — PII may be processed without defined purpose"
}

# 7.3.1: Data subject rights — mechanisms for access, rectification, erasure
deny_no_data_subject_rights contains msg if {
	not input.normalized_data.privacy.data_subject_rights_enabled
	msg := "7.3.1: No data subject rights mechanism — cannot process access, rectification, or erasure requests"
}

# 7.4.1: Privacy by design — PII protection integrated into system design
deny_no_privacy_by_design contains msg if {
	not input.normalized_data.privacy.privacy_impact_assessment_conducted
	msg := "7.4.1: No privacy impact assessment — privacy-by-design not demonstrated"
}

# 7.2.6: Data minimization — collect only necessary PII
deny_excessive_data_collection contains msg if {
	some collection in input.normalized_data.privacy.data_collections
	collection.fields_collected > collection.fields_required
	msg := sprintf("7.2.6: Excessive data collection in '%s' — %d fields collected vs %d required", [
		collection.name,
		collection.fields_collected,
		collection.fields_required,
	])
}

# 7.5.1: PII transfer controls — cross-border transfer safeguards
deny_no_transfer_controls contains msg if {
	some transfer in input.normalized_data.privacy.cross_border_transfers
	not transfer.safeguards_in_place
	msg := sprintf("7.5.1: Cross-border PII transfer to '%s' lacks safeguards", [transfer.destination])
}

default compliant := false

compliant if {
	count(deny_no_purpose_limitation) == 0
	count(deny_no_data_subject_rights) == 0
	count(deny_no_privacy_by_design) == 0
	count(deny_excessive_data_collection) == 0
	count(deny_no_transfer_controls) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_purpose_limitation],
		[f | some f in deny_no_data_subject_rights],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_privacy_by_design],
			[f | some f in deny_excessive_data_collection],
		),
		[f | some f in deny_no_transfer_controls],
	),
)

result := {
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
