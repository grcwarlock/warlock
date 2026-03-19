package iso_27001.a5.a5_02

import rego.v1

# A.5.2: Information Security Roles and Responsibilities
# Validates that security roles are defined and allocated

deny_no_security_roles contains msg if {
	not input.normalized_data.iam.security_roles_defined
	msg := "A.5.2: No dedicated security roles are defined in IAM"
}

deny_no_security_group contains msg if {
	roles := input.normalized_data.iam.roles
	not any_security_role(roles)
	msg := "A.5.2: No IAM role or group contains 'Security' in its name — dedicated security roles required"
}

deny_security_role_no_policy contains msg if {
	some role in input.normalized_data.iam.roles
	contains(lower(role.name), "security")
	count(role.attached_policies) == 0
	msg := sprintf("A.5.2: Security role '%s' has no policies attached", [role.name])
}

deny_no_security_contact contains msg if {
	not input.normalized_data.account.security_contact_configured
	msg := "A.5.2: No security contact is configured for the account"
}

any_security_role(roles) if {
	some role in roles
	contains(lower(role.name), "security")
}

default compliant := false

compliant if {
	count(deny_no_security_roles) == 0
	count(deny_no_security_group) == 0
	count(deny_no_security_contact) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_roles],
		[f | some f in deny_no_security_group],
	),
	array.concat(
		[f | some f in deny_security_role_no_policy],
		[f | some f in deny_no_security_contact],
	),
)

result := {
	"control_id": "A.5.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
