package iso_27001.a6.a6_03

import rego.v1

# A.6.3: Information Security Awareness, Education and Training
# Validates security awareness training is delivered and tracked

deny_users_no_training_tag contains msg if {
	some user in input.normalized_data.users
	not user.tags.SecurityTrainingCompleted
	user.username != "root"
	msg := sprintf("A.6.3: User '%s' has no SecurityTrainingCompleted tag — training status unknown", [user.username])
}

deny_training_expired contains msg if {
	some user in input.normalized_data.users
	user.tags.SecurityTrainingCompleted
	user.training_days_since_completion > 365
	msg := sprintf("A.6.3: User '%s' security training expired %d days ago — annual refresher required", [user.username, user.training_days_since_completion])
}

deny_no_training_config_rule contains msg if {
	not input.normalized_data.config.training_tag_rule_exists
	msg := "A.6.3: No AWS Config rule enforces SecurityTrainingCompleted tag requirement"
}

deny_noncompliant_training_users contains msg if {
	input.normalized_data.config.training_tag_rule_exists
	input.normalized_data.config.training_noncompliant_count > 0
	msg := sprintf("A.6.3: %d users are non-compliant with training tag requirement", [input.normalized_data.config.training_noncompliant_count])
}

default compliant := false

compliant if {
	count(deny_users_no_training_tag) == 0
	count(deny_training_expired) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_users_no_training_tag],
		[f | some f in deny_training_expired],
	),
	array.concat(
		[f | some f in deny_no_training_config_rule],
		[f | some f in deny_noncompliant_training_users],
	),
)

result := {
	"control_id": "A.6.3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
