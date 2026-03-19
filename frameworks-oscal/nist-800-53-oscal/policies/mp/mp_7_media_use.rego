package nist.mp.mp_7

import rego.v1

# MP-7: Media Use

prohibited_media_types := {"usb_flash_drive", "external_hdd", "optical_disc", "floppy_disk"}

deny_prohibited_media contains msg if {
	some media in input.normalized_data.media_protection.active_media
	media.removable
	media.media_type in prohibited_media_types
	not media.exemption_granted
	msg := sprintf("MP-7: Prohibited removable media type '%s' detected on system '%s'", [media.media_type, media.connected_system])
}

deny_removable_no_encryption contains msg if {
	some media in input.normalized_data.media_protection.active_media
	media.removable
	media.exemption_granted
	not media.encrypted
	msg := sprintf("MP-7: Exempted removable media '%s' on '%s' is not encrypted", [media.asset_id, media.connected_system])
}

deny_no_removable_media_policy contains msg if {
	not input.normalized_data.media_protection.removable_media_policy_defined
	msg := "MP-7: Organization has not defined a removable media usage policy"
}

deny_no_media_scanning contains msg if {
	some media in input.normalized_data.media_protection.active_media
	media.removable
	not media.scanned_for_malware
	msg := sprintf("MP-7: Removable media '%s' was not scanned for malware before use", [media.asset_id])
}

default compliant := false

compliant if {
	count(deny_prohibited_media) == 0
	count(deny_removable_no_encryption) == 0
	count(deny_no_removable_media_policy) == 0
	count(deny_no_media_scanning) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_prohibited_media],
		[f | some f in deny_removable_no_encryption],
	),
	array.concat(
		[f | some f in deny_no_removable_media_policy],
		[f | some f in deny_no_media_scanning],
	),
)

result := {
	"control_id": "MP-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
