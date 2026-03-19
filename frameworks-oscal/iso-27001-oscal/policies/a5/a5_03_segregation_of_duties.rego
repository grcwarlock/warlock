package iso_27001.a5.a5_03

import rego.v1

# A.5.3: Segregation of Duties
# Validates that conflicting duties and responsibilities are segregated

deny_no_permission_boundaries contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_admin
	not role.permission_boundary
	msg := sprintf("A.5.3: Admin role '%s' has no permission boundary set", [role.name])
}

deny_user_has_admin_and_audit contains msg if {
	some user in input.normalized_data.users
	user_has_policy(user, "AdministratorAccess")
	user_has_policy(user, "SecurityAudit")
	msg := sprintf("A.5.3: User '%s' has both AdministratorAccess and SecurityAudit — segregation of duties violation", [user.username])
}

deny_single_admin contains msg if {
	admin_count := count([u | some u in input.normalized_data.users; u.is_admin])
	admin_count == 1
	msg := "A.5.3: Only one administrator exists — segregation of duties requires multiple admins"
}

deny_no_segregated_roles contains msg if {
	not input.normalized_data.iam.segregated_roles_exist
	msg := "A.5.3: No segregated IAM roles found for dev/ops/security functions"
}

deny_self_escalation_possible contains msg if {
	some role in input.normalized_data.iam.roles
	not role.is_admin
	role_can_escalate(role)
	msg := sprintf("A.5.3: Role '%s' can potentially self-escalate privileges", [role.name])
}

user_has_policy(user, policy_name) if {
	some p in user.attached_policies
	contains(p, policy_name)
}

role_can_escalate(role) if {
	some action in role.allowed_actions
	action == "iam:AttachRolePolicy"
}

role_can_escalate(role) if {
	some action in role.allowed_actions
	action == "iam:CreateRole"
}

default compliant := false

compliant if {
	count(deny_no_permission_boundaries) == 0
	count(deny_user_has_admin_and_audit) == 0
	count(deny_no_segregated_roles) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_permission_boundaries],
		[f | some f in deny_user_has_admin_and_audit],
	),
	array.concat(
		[f | some f in deny_single_admin],
		array.concat(
			[f | some f in deny_no_segregated_roles],
			[f | some f in deny_self_escalation_possible],
		),
	),
)

result := {
	"control_id": "A.5.3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
