package warlock.iso_27701.pia

import rego.v1

# ISO 27701 Privacy Impact Assessment
# 7.4.1, 7.4.2: PIA/DPIA for high-risk processing

# 7.4.1: Conduct PIA for new processing activities
deny_no_pia contains msg if {
	some processing in input.normalized_data.privacy.processing_activities
	processing.high_risk
	not processing.pia_conducted
	msg := sprintf("7.4.1: High-risk processing '%s' — no privacy impact assessment conducted", [processing.name])
}

# 7.4.2: Review PIA when processing changes
deny_stale_pia contains msg if {
	some processing in input.normalized_data.privacy.processing_activities
	processing.pia_conducted
	processing.processing_changed_since_pia
	not processing.pia_reviewed
	msg := sprintf("7.4.2: Processing '%s' changed since PIA — reassessment needed", [processing.name])
}

# PIA must identify risks and mitigations
deny_no_risk_mitigations contains msg if {
	some processing in input.normalized_data.privacy.processing_activities
	processing.pia_conducted
	not processing.pia_risks_mitigated
	msg := sprintf("7.4.1: PIA for '%s' identified risks but mitigations not documented", [processing.name])
}

# PIA results reviewed by management
deny_no_management_review contains msg if {
	not input.normalized_data.privacy.pia_management_review
	msg := "7.4.1: PIA results not reviewed by management"
}

default compliant := false

compliant if {
	count(deny_no_pia) == 0
	count(deny_stale_pia) == 0
	count(deny_no_risk_mitigations) == 0
	count(deny_no_management_review) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pia],
		[f | some f in deny_stale_pia],
	),
	array.concat(
		[f | some f in deny_no_risk_mitigations],
		[f | some f in deny_no_management_review],
	),
)

result := {
	"control_id": "7.4",
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
