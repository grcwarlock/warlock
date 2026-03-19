package iso_27001.a5.a5_17

import rego.v1

# A.5.17: Authentication Information
# Validates authentication controls including MFA and password policies

deny_weak_password_policy contains msg if {
	policy := input.normalized_data.iam.password_policy
	policy.minimum_password_length < 14
	msg := sprintf("A.5.17: Password minimum length is %d — should be at least 14", [policy.minimum_password_length])
}

deny_no_password_expiry contains msg if {
	policy := input.normalized_data.iam.password_policy
	not policy.max_password_age
	msg := "A.5.17: No password expiry is configured in IAM password policy"
}

deny_low_password_reuse contains msg if {
	policy := input.normalized_data.iam.password_policy
	policy.password_reuse_prevention < 24
	msg := sprintf("A.5.17: Password reuse prevention is %d — should be at least 24", [policy.password_reuse_prevention])
}

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.console_access
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("A.5.17: User '%s' has console access without MFA enabled", [user.username])
}

deny_root_no_mfa contains msg if {
	not input.normalized_data.root_account.mfa_enabled
	msg := "A.5.17: Root account does not have MFA enabled"
}

deny_no_complexity_requirements contains msg if {
	policy := input.normalized_data.iam.password_policy
	not policy.require_symbols
	msg := "A.5.17: Password policy does not require special characters"
}

default compliant := false

compliant if {
	count(deny_weak_password_policy) == 0
	count(deny_no_mfa) == 0
	count(deny_root_no_mfa) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_weak_password_policy],
		[f | some f in deny_no_password_expiry],
	),
	array.concat(
		[f | some f in deny_low_password_reuse],
		array.concat(
			[f | some f in deny_no_mfa],
			array.concat(
				[f | some f in deny_root_no_mfa],
				[f | some f in deny_no_complexity_requirements],
			),
		),
	),
)

result := {
	"control_id": "A.5.17",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
