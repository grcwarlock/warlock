package nist.sc.sc_12

import rego.v1

# SC-12: Cryptographic Key Establishment and Management
# Establish and manage cryptographic keys when cryptography is employed.

deny_unencrypted_resources contains msg if {
	some resource in input.normalized_data.resources
	not resource.encrypted
	msg := sprintf("SC-12: Resource '%s' (%s) is not encrypted at rest", [resource.resource_id, resource.resource_type])
}

deny_default_keys contains msg if {
	some resource in input.normalized_data.resources
	resource.encrypted
	resource.encryption_type == "default"
	resource.key_id == ""
	msg := sprintf("SC-12: Resource '%s' uses default encryption — no customer-managed key (CMK)", [resource.resource_id])
}

deny_no_key_rotation contains msg if {
	some resource in input.normalized_data.resources
	resource.encrypted
	resource.key_rotation_enabled == false
	msg := sprintf("SC-12: Resource '%s' has key rotation disabled", [resource.resource_id])
}

default compliant := false

compliant if {
	count(deny_unencrypted_resources) == 0
	count(deny_default_keys) == 0
	count(deny_no_key_rotation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unencrypted_resources],
		[f | some f in deny_default_keys],
	),
	[f | some f in deny_no_key_rotation],
)

result := {
	"control_id": "SC-12",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
