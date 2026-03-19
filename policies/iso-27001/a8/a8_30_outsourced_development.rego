package iso_27001.a8.a8_30

import rego.v1

# A.8.30: Outsourced Development
# Validates outsourced development access controls and monitoring

deny_vendor_role_no_boundary contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_cross_account
	contains(lower(role.name), "vendor")
	not role.permission_boundary
	msg := sprintf("A.8.30: Vendor role '%s' has no permission boundary set", [role.name])
}

deny_vendor_role_no_mfa contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_cross_account
	contains(lower(role.name), "vendor")
	not role.requires_mfa
	msg := sprintf("A.8.30: Vendor role '%s' does not require MFA for assumption", [role.name])
}

deny_vendor_activity_not_monitored contains msg if {
	not input.normalized_data.cloudtrail.enabled
	msg := "A.8.30: CloudTrail is not enabled — vendor development activity cannot be monitored"
}

deny_vendor_role_no_external_id contains msg if {
	some role in input.normalized_data.iam.roles
	role.is_cross_account
	contains(lower(role.name), "vendor")
	not role.requires_external_id
	msg := sprintf("A.8.30: Vendor role '%s' does not require ExternalId", [role.name])
}

default compliant := false

compliant if {
	count(deny_vendor_role_no_boundary) == 0
	count(deny_vendor_role_no_mfa) == 0
	count(deny_vendor_activity_not_monitored) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_vendor_role_no_boundary],
		[f | some f in deny_vendor_role_no_mfa],
	),
	array.concat(
		[f | some f in deny_vendor_activity_not_monitored],
		[f | some f in deny_vendor_role_no_external_id],
	),
)

result := {
	"control_id": "A.8.30",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
