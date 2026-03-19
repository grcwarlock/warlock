package iso_27001.a8.a8_02

import rego.v1

# A.8.2: Privileged Access Rights
# Validates privileged access is restricted and monitored

deny_admin_users contains msg if {
	some user in input.normalized_data.users
	user.has_admin_access
	msg := sprintf("A.8.2: User '%s' has AdministratorAccess — restrict to role-based access", [user.username])
}

deny_root_access_keys contains msg if {
	input.normalized_data.root_account.access_keys_present
	msg := "A.8.2: Root account has active access keys — remove immediately"
}

deny_root_no_mfa contains msg if {
	not input.normalized_data.root_account.mfa_enabled
	msg := "A.8.2: Root account does not have MFA enabled"
}

deny_no_access_analyzer contains msg if {
	not input.normalized_data.access_analyzer.enabled
	msg := "A.8.2: IAM Access Analyzer is not enabled for privilege analysis"
}

deny_admin_without_mfa contains msg if {
	some user in input.normalized_data.users
	user.has_admin_access
	not user.mfa_enabled
	msg := sprintf("A.8.2: Admin user '%s' does not have MFA enabled — critical risk", [user.username])
}

default compliant := false

compliant if {
	count(deny_root_access_keys) == 0
	count(deny_root_no_mfa) == 0
	count(deny_admin_without_mfa) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_admin_users],
		[f | some f in deny_root_access_keys],
	),
	array.concat(
		[f | some f in deny_root_no_mfa],
		array.concat(
			[f | some f in deny_no_access_analyzer],
			[f | some f in deny_admin_without_mfa],
		),
	),
)

result := {
	"control_id": "A.8.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
