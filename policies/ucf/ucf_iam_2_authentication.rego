package ucf.iam.ucf_iam_2

import rego.v1

# UCF-IAM-2: Authentication
# Validates MFA enforcement and password policy strength

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("UCF-IAM-2: User '%s' does not have MFA enabled", [user.username])
}

deny_weak_password_policy contains msg if {
	policy := input.normalized_data.password_policy
	policy.min_length < 14
	msg := sprintf("UCF-IAM-2: Password minimum length is %d (require 14+)", [policy.min_length])
}

deny_no_password_expiry contains msg if {
	policy := input.normalized_data.password_policy
	policy.max_age_days == 0
	msg := "UCF-IAM-2: No password expiration policy configured"
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_weak_password_policy) == 0
}

findings := array.concat(
	[f | some f in deny_no_mfa],
	array.concat(
		[f | some f in deny_weak_password_policy],
		[f | some f in deny_no_password_expiry],
	),
)

result := {
	"control_id": "UCF-IAM-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
