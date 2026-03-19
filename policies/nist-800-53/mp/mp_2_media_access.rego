package nist.mp.mp_2

import rego.v1

# MP-2: Media Access

deny_unrestricted_media_access contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	not media.access_restricted
	msg := sprintf("MP-2: Media asset '%s' (%s) does not have restricted access controls", [media.asset_id, media.media_type])
}

deny_no_access_list contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	media.contains_sensitive_data
	not media.access_list_defined
	msg := sprintf("MP-2: Sensitive media asset '%s' does not have an access authorization list", [media.asset_id])
}

deny_unauthorized_access contains msg if {
	some access in input.normalized_data.media_protection.access_events
	not access.authorized
	msg := sprintf("MP-2: Unauthorized media access event detected for asset '%s' by user '%s'", [access.asset_id, access.user_id])
}

default compliant := false

compliant if {
	count(deny_unrestricted_media_access) == 0
	count(deny_no_access_list) == 0
	count(deny_unauthorized_access) == 0
}

findings := array.concat(
	[f | some f in deny_unrestricted_media_access],
	array.concat(
		[f | some f in deny_no_access_list],
		[f | some f in deny_unauthorized_access],
	),
)

result := {
	"control_id": "MP-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
