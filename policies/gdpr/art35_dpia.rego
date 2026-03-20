package gdpr.art35

import rego.v1

# GDPR Article 35: Data Protection Impact Assessment (DPIA)
# Required for high-risk processing activities

deny_no_dpia contains msg if {
	some activity in input.normalized_data.processing_activities
	activity.high_risk
	not activity.dpia_completed
	msg := sprintf("Art35: High-risk processing activity '%s' requires a DPIA but none completed", [activity.name])
}

deny_stale_dpia contains msg if {
	some activity in input.normalized_data.processing_activities
	activity.high_risk
	activity.dpia_completed
	activity.dpia_days_since_review > 365
	msg := sprintf("Art35: DPIA for '%s' last reviewed %d days ago — annual review required", [activity.name, activity.dpia_days_since_review])
}

deny_no_dpia_policy contains msg if {
	not input.normalized_data.policies.dpia_policy_documented
	msg := "Art35: No documented DPIA policy — must define criteria for when DPIAs are required"
}

default compliant := false

compliant if {
	count(deny_no_dpia) == 0
	count(deny_stale_dpia) == 0
	count(deny_no_dpia_policy) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_dpia],
		[f | some f in deny_stale_dpia],
	),
	[f | some f in deny_no_dpia_policy],
)

result := {
	"control_id": "Art35",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
