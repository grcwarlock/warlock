package nist.mp.mp_1

import rego.v1

# MP-1: Media Protection Policy and Procedures

deny_no_media_policy contains msg if {
	not input.normalized_data.media_protection.policy_defined
	msg := "MP-1: Organization has not defined a media protection policy"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.media_protection.policy_defined
	not input.normalized_data.media_protection.policy_reviewed_within_365_days
	msg := "MP-1: Media protection policy has not been reviewed within the last 365 days"
}

deny_no_procedures contains msg if {
	not input.normalized_data.media_protection.procedures_documented
	msg := "MP-1: Media protection procedures are not documented"
}

deny_no_designated_official contains msg if {
	not input.normalized_data.media_protection.designated_official
	msg := "MP-1: No designated official assigned for media protection policy management"
}

default compliant := false

compliant if {
	count(deny_no_media_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_procedures) == 0
	count(deny_no_designated_official) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_media_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_procedures],
		[f | some f in deny_no_designated_official],
	),
)

result := {
	"control_id": "MP-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
