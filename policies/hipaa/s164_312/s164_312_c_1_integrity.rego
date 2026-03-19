package hipaa.s164_312.s164_312_c_1

import rego.v1

# 164.312(c)(1): Integrity
# Requires policies and procedures to protect ePHI from improper
# alteration or destruction

deny_no_integrity_controls contains msg if {
	not input.normalized_data.config.integrity_verification_enabled
	msg := "164.312(c)(1): No integrity verification mechanism — must implement electronic mechanisms to corroborate that ePHI has not been improperly altered or destroyed"
}

deny_no_versioning contains msg if {
	some resource in input.normalized_data.resources.datastores
	resource.contains_ephi
	not resource.versioning_enabled
	msg := sprintf("164.312(c)(1): Datastore '%s' containing ePHI does not have versioning enabled — unable to detect or recover from improper alteration", [resource.name])
}

deny_no_checksum_validation contains msg if {
	some resource in input.normalized_data.resources.datastores
	resource.contains_ephi
	not resource.checksum_validation
	msg := sprintf("164.312(c)(1): Datastore '%s' containing ePHI does not have checksum validation for data integrity", [resource.name])
}

default compliant := false

compliant if {
	count(deny_no_integrity_controls) == 0
	count(deny_no_versioning) == 0
	count(deny_no_checksum_validation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_integrity_controls],
		[f | some f in deny_no_versioning],
	),
	[f | some f in deny_no_checksum_validation],
)

result := {
	"control_id": "164.312(c)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
