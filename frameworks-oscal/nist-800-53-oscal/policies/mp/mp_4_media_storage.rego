package nist.mp.mp_4

import rego.v1

# MP-4: Media Storage

deny_unsecured_storage contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	media.contains_sensitive_data
	not media.stored_securely
	msg := sprintf("MP-4: Sensitive media asset '%s' is not stored in a secured location", [media.asset_id])
}

deny_no_encryption_at_rest contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	media.digital
	media.contains_sensitive_data
	not media.encrypted_at_rest
	msg := sprintf("MP-4: Digital media asset '%s' containing sensitive data is not encrypted at rest", [media.asset_id])
}

deny_no_physical_lock contains msg if {
	some media in input.normalized_data.media_protection.media_assets
	not media.digital
	media.contains_sensitive_data
	not media.physically_locked
	msg := sprintf("MP-4: Physical media asset '%s' containing sensitive data is not in a locked container", [media.asset_id])
}

deny_no_inventory contains msg if {
	not input.normalized_data.media_protection.media_inventory_maintained
	msg := "MP-4: Organization does not maintain an inventory of media assets"
}

default compliant := false

compliant if {
	count(deny_unsecured_storage) == 0
	count(deny_no_encryption_at_rest) == 0
	count(deny_no_physical_lock) == 0
	count(deny_no_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unsecured_storage],
		[f | some f in deny_no_encryption_at_rest],
	),
	array.concat(
		[f | some f in deny_no_physical_lock],
		[f | some f in deny_no_inventory],
	),
)

result := {
	"control_id": "MP-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
