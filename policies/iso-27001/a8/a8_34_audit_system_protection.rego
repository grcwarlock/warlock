package iso_27001.a8.a8_34

import rego.v1

# A.8.34: Protection of Information Systems During Audit Testing
# Validates audit testing controls and read-only access for auditors

deny_no_auditor_role contains msg if {
	not input.normalized_data.iam.auditor_role_exists
	msg := "A.8.34: No dedicated auditor IAM role with read-only access"
}

deny_auditor_role_not_readonly contains msg if {
	some role in input.normalized_data.iam.roles
	contains(lower(role.name), "auditor")
	not role.is_read_only
	msg := sprintf("A.8.34: Auditor role '%s' has write permissions — should be read-only", [role.name])
}

deny_auditor_no_boundary contains msg if {
	some role in input.normalized_data.iam.roles
	contains(lower(role.name), "auditor")
	not role.permission_boundary
	msg := sprintf("A.8.34: Auditor role '%s' has no permission boundary — scope unrestricted", [role.name])
}

deny_auditor_long_session contains msg if {
	some role in input.normalized_data.iam.roles
	contains(lower(role.name), "auditor")
	role.max_session_duration > 3600
	msg := sprintf("A.8.34: Auditor role '%s' allows sessions up to %d seconds — limit to 1 hour", [role.name, role.max_session_duration])
}

deny_auditor_activity_not_logged contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.8.34: CloudTrail is not enabled — auditor activity cannot be monitored"
}

default compliant := false

compliant if {
	count(deny_no_auditor_role) == 0
	count(deny_auditor_role_not_readonly) == 0
	count(deny_auditor_activity_not_logged) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_auditor_role],
		[f | some f in deny_auditor_role_not_readonly],
	),
	array.concat(
		[f | some f in deny_auditor_no_boundary],
		array.concat(
			[f | some f in deny_auditor_long_session],
			[f | some f in deny_auditor_activity_not_logged],
		),
	),
)

result := {
	"control_id": "A.8.34",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
