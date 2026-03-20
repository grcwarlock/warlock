package pci_dss.r8

import rego.v1

# PCI DSS 4.0 Requirement 8: Identify Users and Authenticate Access

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	msg := sprintf("R8.4: User '%s' does not have MFA enabled for CDE access", [user.username])
}

deny_weak_password_policy contains msg if {
	policy := input.normalized_data.password_policy
	policy.min_length < 12
	msg := sprintf("R8.3: Password policy minimum length is %d (requires 12+)", [policy.min_length])
}

deny_shared_accounts contains msg if {
	some account in input.normalized_data.service_accounts
	account.shared
	not account.managed
	msg := sprintf("R8.6: Shared account '%s' is not managed via PAM", [account.name])
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_weak_password_policy) == 0
	count(deny_shared_accounts) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_weak_password_policy],
	),
	[f | some f in deny_shared_accounts],
)

result := {
	"control_id": "R8",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
