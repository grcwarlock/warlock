package iso_27001.a5.a5_16

import rego.v1

# A.5.16: Identity Management
# Validates the full life cycle of identities is managed

deny_no_sso contains msg if {
	not input.normalized_data.sso.enabled
	msg := "A.5.16: IAM Identity Center (SSO) is not enabled for centralized identity management"
}

deny_stale_credentials contains msg if {
	some user in input.normalized_data.users
	user.password_last_used_days > 90
	user.console_access
	msg := sprintf("A.5.16: User '%s' has not used console in %d days — stale credential", [user.username, user.password_last_used_days])
}

deny_stale_access_keys contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	msg := sprintf("A.5.16: User '%s' has access key unused for %d days", [user.username, key.last_used_days])
}

deny_no_credential_report contains msg if {
	not input.normalized_data.iam.credential_report_generated
	msg := "A.5.16: IAM credential report has not been generated recently"
}

deny_users_without_groups contains msg if {
	some user in input.normalized_data.users
	count(user.groups) == 0
	user.username != "root"
	msg := sprintf("A.5.16: User '%s' is not assigned to any IAM group — identity lifecycle not managed", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_sso) == 0
	count(deny_stale_credentials) == 0
	count(deny_stale_access_keys) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_sso],
		[f | some f in deny_stale_credentials],
	),
	array.concat(
		[f | some f in deny_stale_access_keys],
		array.concat(
			[f | some f in deny_no_credential_report],
			[f | some f in deny_users_without_groups],
		),
	),
)

result := {
	"control_id": "A.5.16",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
