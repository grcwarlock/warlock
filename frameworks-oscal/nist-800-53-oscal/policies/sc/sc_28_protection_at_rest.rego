package nist.sc.sc_28

import rego.v1

# SC-28: Protection of Information at Rest
# Protect the confidentiality and integrity of information at rest.

deny_unencrypted contains msg if {
	some resource in input.normalized_data.resources
	not resource.encrypted
	msg := sprintf("SC-28: Resource '%s' (%s) stores data without encryption at rest", [resource.resource_id, resource.resource_type])
}

deny_weak_encryption contains msg if {
	some resource in input.normalized_data.resources
	resource.encrypted
	resource.encryption_type == "SSE-S3"
	msg := sprintf("SC-28: Resource '%s' uses basic server-side encryption (SSE-S3) — consider SSE-KMS or SSE-C", [resource.resource_id])
}

default compliant := false

compliant if {
	count(deny_unencrypted) == 0
	count(deny_weak_encryption) == 0
}

findings := array.concat(
	[f | some f in deny_unencrypted],
	[f | some f in deny_weak_encryption],
)

result := {
	"control_id": "SC-28",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
