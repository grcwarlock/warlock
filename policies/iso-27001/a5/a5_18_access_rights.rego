package iso_27001.a5.a5_18

import rego.v1

# A.5.18: Access Rights
# Validates access rights are regularly reviewed and appropriate

deny_unused_credentials contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	msg := sprintf("A.5.18: User '%s' has access key unused for %d days — review and remove", [user.username, key.last_used_days])
}

deny_no_unused_credentials_rule contains msg if {
	not input.normalized_data.config.unused_credentials_rule_exists
	msg := "A.5.18: No AWS Config rule monitors for unused credentials"
}

deny_unused_access_findings contains msg if {
	some finding in input.normalized_data.access_analyzer.findings
	finding.finding_type == "UNUSED_ACCESS"
	finding.status == "ACTIVE"
	msg := sprintf("A.5.18: Unused access finding on '%s' — permissions should be removed", [finding.resource])
}

deny_no_access_review_process contains msg if {
	not input.normalized_data.policies.access_review_process_documented
	msg := "A.5.18: No periodic access review process is documented"
}

deny_old_access_keys contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.age_days > 180
	msg := sprintf("A.5.18: User '%s' has access key older than 180 days — rotate immediately", [user.username])
}

default compliant := false

compliant if {
	count(deny_unused_credentials) == 0
	count(deny_no_unused_credentials_rule) == 0
	count(deny_unused_access_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unused_credentials],
		[f | some f in deny_no_unused_credentials_rule],
	),
	array.concat(
		[f | some f in deny_unused_access_findings],
		array.concat(
			[f | some f in deny_no_access_review_process],
			[f | some f in deny_old_access_keys],
		),
	),
)

result := {
	"control_id": "A.5.18",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
