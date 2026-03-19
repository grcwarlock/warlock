package iso_27001.a8.a8_05

import rego.v1

# A.8.5: Secure Authentication
# Validates secure authentication mechanisms including MFA and password policies

deny_weak_password_length contains msg if {
	policy := input.normalized_data.iam.password_policy
	policy.minimum_password_length < 14
	msg := sprintf("A.8.5: Password minimum length is %d — should be at least 14", [policy.minimum_password_length])
}

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.console_access
	not user.mfa_enabled
	msg := sprintf("A.8.5: User '%s' has console access without MFA", [user.username])
}

deny_root_no_mfa contains msg if {
	not input.normalized_data.root_account.mfa_enabled
	msg := "A.8.5: Root account MFA is not enabled"
}

deny_no_password_complexity contains msg if {
	policy := input.normalized_data.iam.password_policy
	not policy.require_uppercase_characters
	msg := "A.8.5: Password policy does not require uppercase characters"
}

deny_no_saml_provider contains msg if {
	count(input.normalized_data.iam.saml_providers) == 0
	input.normalized_data.users_count > 10
	msg := "A.8.5: No SAML identity provider configured — federated authentication recommended for organizations"
}

default compliant := false

compliant if {
	count(deny_weak_password_length) == 0
	count(deny_no_mfa) == 0
	count(deny_root_no_mfa) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_weak_password_length],
		[f | some f in deny_no_mfa],
	),
	array.concat(
		[f | some f in deny_root_no_mfa],
		array.concat(
			[f | some f in deny_no_password_complexity],
			[f | some f in deny_no_saml_provider],
		),
	),
)

result := {
	"control_id": "A.8.5",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
