package cmmc.mp.mp_l2_3_8_1

import rego.v1

# MP.L2-3.8.1: Media Protection
# Protect (i.e., physically control and securely store) system media containing CUI

deny_unencrypted_storage contains msg if {
	some storage in input.normalized_data.storage_resources
	storage.contains_cui
	not storage.encrypted
	msg := sprintf("MP.L2-3.8.1: Storage resource '%s' contains CUI but is not encrypted", [storage.name])
}

deny_no_access_control_on_media contains msg if {
	some storage in input.normalized_data.storage_resources
	storage.contains_cui
	storage.publicly_accessible
	msg := sprintf("MP.L2-3.8.1: Storage resource '%s' containing CUI is publicly accessible", [storage.name])
}

deny_no_media_sanitization contains msg if {
	some storage in input.normalized_data.storage_resources
	storage.decommissioned
	not storage.sanitized
	msg := sprintf("MP.L2-3.8.1: Decommissioned storage '%s' has not been sanitized per NIST SP 800-88", [storage.name])
}

default compliant := false

compliant if {
	count(deny_unencrypted_storage) == 0
	count(deny_no_access_control_on_media) == 0
	count(deny_no_media_sanitization) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unencrypted_storage],
		[f | some f in deny_no_access_control_on_media],
	),
	[f | some f in deny_no_media_sanitization],
)

result := {
	"control_id": "MP.L2-3.8.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
