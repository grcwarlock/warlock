package iso_27001.a5.a5_19

import rego.v1

# A.5.19: Information Security in Supplier Relationships
# Validates supplier security requirements are documented and monitored

deny_supplier_role_no_external_id contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_cross_account
	not role.requires_external_id
	msg := sprintf("A.5.19: Cross-account role '%s' does not require ExternalId — supplier access insecure", [role.name])
}

deny_supplier_access_not_logged contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.5.19: CloudTrail is not enabled — supplier access cannot be monitored"
}

deny_no_supplier_security_policy contains msg if {
	not input.normalized_data.policies.supplier_security_policy
	msg := "A.5.19: No supplier security requirements policy is documented"
}

deny_supplier_role_overprivileged contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_cross_account
	role.has_admin_access
	msg := sprintf("A.5.19: Cross-account supplier role '%s' has administrative access — violates least privilege", [role.name])
}

default compliant := false

compliant if {
	count(deny_supplier_role_no_external_id) == 0
	count(deny_supplier_access_not_logged) == 0
	count(deny_supplier_role_overprivileged) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_supplier_role_no_external_id],
		[f | some f in deny_supplier_access_not_logged],
	),
	array.concat(
		[f | some f in deny_no_supplier_security_policy],
		[f | some f in deny_supplier_role_overprivileged],
	),
)

result := {
	"control_id": "A.5.19",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
