package iso_27001.a5.a5_15

import rego.v1

# A.5.15: Access Control
# Validates access control policies enforce least privilege

deny_no_access_analyzer contains msg if {
	not input.normalized_data.access_analyzer.enabled
	msg := "A.5.15: IAM Access Analyzer is not enabled — cannot detect over-permissive access"
}

deny_external_access_findings contains msg if {
	input.normalized_data.access_analyzer.enabled
	some finding in input.normalized_data.access_analyzer.findings
	finding.status == "ACTIVE"
	finding.is_external
	msg := sprintf("A.5.15: Access Analyzer found external access on '%s' (%s)", [finding.resource, finding.resource_type])
}

deny_wildcard_policies contains msg if {
	some user in input.normalized_data.users
	some policy in user.inline_policies
	policy.has_wildcard_resource
	policy.has_wildcard_action
	msg := sprintf("A.5.15: User '%s' has inline policy with wildcard actions and resources — violates least privilege", [user.username])
}

deny_no_mfa_for_console contains msg if {
	some user in input.normalized_data.users
	user.console_access
	not user.mfa_enabled
	msg := sprintf("A.5.15: User '%s' has console access without MFA", [user.username])
}

deny_root_access_keys contains msg if {
	input.normalized_data.root_account.access_keys_present
	msg := "A.5.15: Root account has active access keys — remove immediately"
}

default compliant := false

compliant if {
	count(deny_no_access_analyzer) == 0
	count(deny_external_access_findings) == 0
	count(deny_wildcard_policies) == 0
	count(deny_root_access_keys) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_access_analyzer],
		[f | some f in deny_external_access_findings],
	),
	array.concat(
		[f | some f in deny_wildcard_policies],
		array.concat(
			[f | some f in deny_no_mfa_for_console],
			[f | some f in deny_root_access_keys],
		),
	),
)

result := {
	"control_id": "A.5.15",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
