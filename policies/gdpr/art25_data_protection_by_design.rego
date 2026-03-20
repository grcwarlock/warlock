package gdpr.art25

import rego.v1

# GDPR Article 25: Data protection by design and by default

deny_no_encryption contains msg if {
	some resource in input.normalized_data.storage_resources
	not resource.encryption_enabled
	msg := sprintf("Art25: Resource '%s' lacks encryption — data protection by design requires encryption at rest", [resource.name])
}

deny_public_storage contains msg if {
	some resource in input.normalized_data.storage_resources
	resource.public_access
	msg := sprintf("Art25: Resource '%s' has public access enabled — violates data protection by default", [resource.name])
}

deny_no_dpia contains msg if {
	some activity in input.normalized_data.processing_activities
	activity.high_risk
	not activity.dpia_completed
	msg := sprintf("Art25: High-risk processing activity '%s' has no DPIA completed", [activity.name])
}

default compliant := false

compliant if {
	count(deny_no_encryption) == 0
	count(deny_public_storage) == 0
	count(deny_no_dpia) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_encryption],
		[f | some f in deny_public_storage],
	),
	[f | some f in deny_no_dpia],
)

result := {
	"control_id": "Art25",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
