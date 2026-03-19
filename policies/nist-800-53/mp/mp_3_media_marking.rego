package nist.mp.mp_3

import rego.v1

# MP-3: Media Marking

valid_classifications := {"public", "internal", "confidential", "restricted", "top_secret"}

deny_unmarked_media contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	not media.classification_label
	msg := sprintf("MP-3: Media asset '%s' (%s) does not have a data classification label", [media.asset_id, media.media_type])
}

deny_invalid_classification contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	media.classification_label
	not media.classification_label in valid_classifications
	msg := sprintf("MP-3: Media asset '%s' has invalid classification label '%s'", [media.asset_id, media.classification_label])
}

deny_sensitive_not_marked contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	media.contains_sensitive_data
	media.classification_label == "public"
	msg := sprintf("MP-3: Media asset '%s' contains sensitive data but is marked as 'public'", [media.asset_id])
}

default compliant := false

compliant if {
	count(deny_unmarked_media) == 0
	count(deny_invalid_classification) == 0
	count(deny_sensitive_not_marked) == 0
}

findings := array.concat(
	[f | some f in deny_unmarked_media],
	array.concat(
		[f | some f in deny_invalid_classification],
		[f | some f in deny_sensitive_not_marked],
	),
)

result := {
	"control_id": "MP-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
