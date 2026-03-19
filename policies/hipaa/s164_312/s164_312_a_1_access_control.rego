package hipaa.s164_312.s164_312_a_1

import rego.v1

# 164.312(a)(1): Access Control
# Requires technical policies and procedures to allow access only to
# authorized persons or software programs

deny_no_unique_user_id contains msg if {
	some user in input.normalized_data.users
	not user.unique_id
	msg := sprintf("164.312(a)(1): User '%s' does not have a unique user identifier assigned", [user.username])
}

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.ephi_access
	not user.mfa_enabled
	msg := sprintf("164.312(a)(1): User '%s' with ePHI access does not have MFA enabled", [user.username])
}

deny_no_auto_logoff contains msg if {
	not input.normalized_data.config.session_timeout_enabled
	msg := "164.312(a)(1): Automatic logoff is not configured — must terminate sessions after a period of inactivity"
}

deny_no_emergency_access_procedure contains msg if {
	not input.normalized_data.policies.emergency_access_procedure
	msg := "164.312(a)(1): No emergency access procedure — must establish procedures for obtaining necessary ePHI during an emergency"
}

default compliant := false

compliant if {
	count(deny_no_unique_user_id) == 0
	count(deny_no_mfa) == 0
	count(deny_no_auto_logoff) == 0
	count(deny_no_emergency_access_procedure) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_unique_user_id],
		[f | some f in deny_no_mfa],
	),
	array.concat(
		[f | some f in deny_no_auto_logoff],
		[f | some f in deny_no_emergency_access_procedure],
	),
)

result := {
	"control_id": "164.312(a)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
