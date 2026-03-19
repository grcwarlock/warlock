package cmmc.ac.ac_l2_3_1_1

import rego.v1

# AC.L2-3.1.1: Authorized Access Control
# Limit system access to authorized users, processes, and devices

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	msg := sprintf("AC.L2-3.1.1: User '%s' does not have MFA enabled for system access", [user.username])
}

deny_inactive_user contains msg if {
	some user in input.normalized_data.users
	user.last_login_days > 90
	user.enabled
	msg := sprintf("AC.L2-3.1.1: User '%s' has not logged in for %d days but account is still enabled", [user.username, user.last_login_days])
}

deny_no_session_timeout contains msg if {
	some system in input.normalized_data.systems
	not system.session_timeout_configured
	msg := sprintf("AC.L2-3.1.1: System '%s' does not enforce session timeout for idle users", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_inactive_user) == 0
	count(deny_no_session_timeout) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_inactive_user],
	),
	[f | some f in deny_no_session_timeout],
)

result := {
	"control_id": "AC.L2-3.1.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
