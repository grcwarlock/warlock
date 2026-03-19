package nist.pl.pl_4

import rego.v1

# PL-4: Rules of Behavior

deny_no_rules_of_behavior contains msg if {
	not input.normalized_data.planning.rules_of_behavior_defined
	msg := "PL-4: Organization has not defined rules of behavior (acceptable use policy)"
}

deny_rules_not_signed contains msg if {
	some user in input.normalized_data.planning.users
	not user.rules_of_behavior_signed
	msg := sprintf("PL-4: User '%s' has not signed the rules of behavior / acceptable use policy", [user.user_id])
}

deny_rules_not_reviewed contains msg if {
	input.normalized_data.planning.rules_of_behavior_defined
	not input.normalized_data.planning.rules_of_behavior_reviewed_within_365_days
	msg := "PL-4: Rules of behavior have not been reviewed and updated within the last 365 days"
}

deny_no_consequence_definition contains msg if {
	input.normalized_data.planning.rules_of_behavior_defined
	not input.normalized_data.planning.rules_of_behavior_defines_consequences
	msg := "PL-4: Rules of behavior do not define consequences for non-compliance"
}

deny_no_social_media_restrictions contains msg if {
	input.normalized_data.planning.rules_of_behavior_defined
	not input.normalized_data.planning.rules_of_behavior_covers_social_media
	msg := "PL-4: Rules of behavior do not address social media and networking restrictions"
}

default compliant := false

compliant if {
	count(deny_no_rules_of_behavior) == 0
	count(deny_rules_not_signed) == 0
	count(deny_rules_not_reviewed) == 0
	count(deny_no_consequence_definition) == 0
	count(deny_no_social_media_restrictions) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_rules_of_behavior],
		[f | some f in deny_rules_not_signed],
	),
	array.concat(
		array.concat(
			[f | some f in deny_rules_not_reviewed],
			[f | some f in deny_no_consequence_definition],
		),
		[f | some f in deny_no_social_media_restrictions],
	),
)

result := {
	"control_id": "PL-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
