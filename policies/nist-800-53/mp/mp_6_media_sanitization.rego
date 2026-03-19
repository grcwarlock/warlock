package nist.mp.mp_6

import rego.v1

# MP-6: Media Sanitization

approved_sanitization_methods := {"clear", "purge", "destroy", "cryptographic_erase"}

deny_no_sanitization contains msg if {
	some media in input.normalized_data.media_protection.decommissioned_media
	not media.sanitized
	msg := sprintf("MP-6: Decommissioned media '%s' has not been sanitized", [media.asset_id])
}

deny_invalid_method contains msg if {
	some media in input.normalized_data.media_protection.decommissioned_media
	media.sanitized
	not media.sanitization_method in approved_sanitization_methods
	msg := sprintf("MP-6: Media '%s' was sanitized using unapproved method '%s'", [media.asset_id, media.sanitization_method])
}

deny_no_sanitization_verification contains msg if {
	some media in input.normalized_data.media_protection.decommissioned_media
	media.sanitized
	not media.sanitization_verified
	msg := sprintf("MP-6: Sanitization of media '%s' was not independently verified", [media.asset_id])
}

deny_no_sanitization_record contains msg if {
	some media in input.normalized_data.media_protection.decommissioned_media
	media.sanitized
	not media.sanitization_record_kept
	msg := sprintf("MP-6: No sanitization record maintained for media '%s'", [media.asset_id])
}

default compliant := false

compliant if {
	count(deny_no_sanitization) == 0
	count(deny_invalid_method) == 0
	count(deny_no_sanitization_verification) == 0
	count(deny_no_sanitization_record) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_sanitization],
		[f | some f in deny_invalid_method],
	),
	array.concat(
		[f | some f in deny_no_sanitization_verification],
		[f | some f in deny_no_sanitization_record],
	),
)

result := {
	"control_id": "MP-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
