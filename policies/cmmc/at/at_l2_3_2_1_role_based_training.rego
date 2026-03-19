package cmmc.at.at_l2_3_2_1

import rego.v1

# AT.L2-3.2.1: Role-Based Security Awareness Training
# Ensure personnel are trained to carry out their assigned information security-related duties

deny_no_security_training contains msg if {
	some user in input.normalized_data.users
	user.enabled
	not user.security_training_completed
	msg := sprintf("AT.L2-3.2.1: User '%s' has not completed required security awareness training", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.enabled
	user.security_training_completed
	user.training_age_days > 365
	msg := sprintf("AT.L2-3.2.1: User '%s' security training expired %d days ago — annual renewal required", [user.username, user.training_age_days])
}

deny_no_role_specific_training contains msg if {
	some user in input.normalized_data.users
	user.privileged
	not user.role_specific_training_completed
	msg := sprintf("AT.L2-3.2.1: Privileged user '%s' has not completed role-specific security training", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_security_training) == 0
	count(deny_training_expired) == 0
	count(deny_no_role_specific_training) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_training],
		[f | some f in deny_training_expired],
	),
	[f | some f in deny_no_role_specific_training],
)

result := {
	"control_id": "AT.L2-3.2.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
