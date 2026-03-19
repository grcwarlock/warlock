package nist.at.at_3

import rego.v1

# AT-3: Role-Based Training
# Validates role-based security training for personnel with assigned security roles

deny_no_role_based_training contains msg if {
	not input.normalized_data.role_based_training
	msg := "AT-3: No role-based security training program configured"
}

deny_admin_no_training contains msg if {
	some user in input.normalized_data.users
	user.role == "admin"
	not user.role_based_training_completed
	msg := sprintf("AT-3: Administrator '%s' has not completed role-based security training", [user.username])
}

deny_security_role_no_training contains msg if {
	some user in input.normalized_data.users
	user.role == "security"
	not user.role_based_training_completed
	msg := sprintf("AT-3: Security personnel '%s' has not completed role-based training", [user.username])
}

deny_role_training_expired contains msg if {
	some user in input.normalized_data.users
	user.role_based_training_completed
	user.role_training_completion_days > 365
	msg := sprintf("AT-3: User '%s' role-based training expired (%d days since completion)", [user.username, user.role_training_completion_days])
}

deny_no_privileged_user_training contains msg if {
	some user in input.normalized_data.users
	user.privileged_access
	not user.privileged_role_training_completed
	msg := sprintf("AT-3: Privileged user '%s' has not completed privileged access training", [user.username])
}

deny_no_training_curriculum contains msg if {
	input.normalized_data.role_based_training
	not input.normalized_data.role_based_training.curriculum_defined
	msg := "AT-3: Role-based training curriculum has not been defined for security roles"
}

default compliant := false

compliant if {
	count(deny_no_role_based_training) == 0
	count(deny_admin_no_training) == 0
	count(deny_security_role_no_training) == 0
	count(deny_role_training_expired) == 0
	count(deny_no_privileged_user_training) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_role_based_training],
		[f | some f in deny_admin_no_training],
	),
	array.concat(
		[f | some f in deny_security_role_no_training],
		array.concat(
			[f | some f in deny_role_training_expired],
			array.concat(
				[f | some f in deny_no_privileged_user_training],
				[f | some f in deny_no_training_curriculum],
			),
		),
	),
)

result := {
	"control_id": "AT-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
