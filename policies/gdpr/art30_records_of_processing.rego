package gdpr.art30

import rego.v1

# GDPR Article 30: Records of processing activities (ROPA)

deny_no_ropa contains msg if {
	not input.normalized_data.privacy.ropa_maintained
	msg := "Art30: No Records of Processing Activities (ROPA) maintained"
}

deny_ropa_stale contains msg if {
	input.normalized_data.privacy.ropa_maintained
	input.normalized_data.privacy.ropa_days_since_update > 365
	msg := sprintf("Art30: ROPA last updated %d days ago — must be reviewed at least annually", [input.normalized_data.privacy.ropa_days_since_update])
}

deny_incomplete_ropa contains msg if {
	some activity in input.normalized_data.processing_activities
	not activity.recorded_in_ropa
	msg := sprintf("Art30: Processing activity '%s' is not recorded in ROPA", [activity.name])
}

default compliant := false

compliant if {
	count(deny_no_ropa) == 0
	count(deny_ropa_stale) == 0
	count(deny_incomplete_ropa) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ropa],
		[f | some f in deny_ropa_stale],
	),
	[f | some f in deny_incomplete_ropa],
)

result := {
	"control_id": "Art30",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
