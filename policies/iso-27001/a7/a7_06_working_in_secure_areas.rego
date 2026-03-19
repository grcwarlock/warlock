package iso_27001.a7.a7_06

import rego.v1

# A.7.6: Working in Secure Areas
# Validates access controls for secure/restricted environments

deny_no_restricted_access_policies contains msg if {
	not input.normalized_data.iam.restricted_access_policies_exist
	msg := "A.7.6: No IAM policies restrict access to production/secure environments"
}

deny_no_session_logging contains msg if {
	not input.normalized_data.ssm.session_logging_enabled
	msg := "A.7.6: SSM session logging is not enabled for secure area access auditing"
}

deny_no_restricted_group contains msg if {
	not input.normalized_data.iam.secure_area_access_group_exists
	msg := "A.7.6: No dedicated IAM group for secure area access control"
}

deny_production_wide_access contains msg if {
	some role in input.normalized_data.iam.roles
	role.tags.Environment == "Production"
	role.has_wildcard_resource
	msg := sprintf("A.7.6: Production role '%s' has wildcard resource access — restrict scope", [role.name])
}

default compliant := false

compliant if {
	count(deny_no_restricted_access_policies) == 0
	count(deny_no_session_logging) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_restricted_access_policies],
		[f | some f in deny_no_session_logging],
	),
	array.concat(
		[f | some f in deny_no_restricted_group],
		[f | some f in deny_production_wide_access],
	),
)

result := {
	"control_id": "A.7.6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
