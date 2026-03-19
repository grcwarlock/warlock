package iso_27001.a6.a6_01

import rego.v1

# A.6.1: Screening
# Validates background screening processes are documented and enforced

deny_users_missing_screening_tag contains msg if {
	some user in input.normalized_data.users
	not user.tags.ScreeningCompleted
	user.username != "root"
	msg := sprintf("A.6.1: User '%s' is missing ScreeningCompleted tag — background check status unknown", [user.username])
}

deny_screening_tag_false contains msg if {
	some user in input.normalized_data.users
	user.tags.ScreeningCompleted == "false"
	msg := sprintf("A.6.1: User '%s' has ScreeningCompleted=false — access should not be provisioned", [user.username])
}

deny_no_screening_config_rule contains msg if {
	not input.normalized_data.config.screening_tag_rule_exists
	msg := "A.6.1: No AWS Config rule enforces ScreeningCompleted tag on IAM users"
}

deny_no_screening_process contains msg if {
	not input.normalized_data.policies.screening_process_documented
	msg := "A.6.1: No documented background screening process exists"
}

default compliant := false

compliant if {
	count(deny_users_missing_screening_tag) == 0
	count(deny_screening_tag_false) == 0
	count(deny_no_screening_process) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_users_missing_screening_tag],
		[f | some f in deny_screening_tag_false],
	),
	array.concat(
		[f | some f in deny_no_screening_config_rule],
		[f | some f in deny_no_screening_process],
	),
)

result := {
	"control_id": "A.6.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
