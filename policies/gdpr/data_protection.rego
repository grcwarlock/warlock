package warlock.gdpr

import rego.v1

# GDPR Data Protection Rules
# General Data Protection Regulation enforcement policies

# Art. 5(1)(b): Purpose limitation — personal data collected for specified purposes
deny_no_purpose_specification contains msg if {
	not input.normalized_data.data_protection.processing_purposes_documented
	msg := "Art.5(1)(b): Processing purposes not documented — purpose limitation violated"
}

# Art. 25: Data protection by design and by default
deny_no_dpia contains msg if {
	some processing in input.normalized_data.data_protection.high_risk_processing
	not processing.dpia_completed
	msg := sprintf("Art.25: High-risk processing '%s' lacks DPIA", [processing.name])
}

# Art. 30: Records of processing activities
deny_no_ropa contains msg if {
	not input.normalized_data.data_protection.records_of_processing_maintained
	msg := "Art.30: No records of processing activities maintained"
}

# Art. 33: Breach notification — 72-hour notification capability
deny_no_breach_notification contains msg if {
	not input.normalized_data.data_protection.breach_notification_process
	msg := "Art.33: No breach notification process — 72-hour supervisory authority notification at risk"
}

# Art. 32: Security of processing — encryption and pseudonymization
deny_no_encryption contains msg if {
	some system in input.normalized_data.data_protection.systems_processing_personal_data
	not system.encryption_at_rest
	msg := sprintf("Art.32: System '%s' processes personal data without encryption at rest", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_purpose_specification) == 0
	count(deny_no_dpia) == 0
	count(deny_no_ropa) == 0
	count(deny_no_breach_notification) == 0
	count(deny_no_encryption) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_purpose_specification],
		[f | some f in deny_no_dpia],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_ropa],
			[f | some f in deny_no_breach_notification],
		),
		[f | some f in deny_no_encryption],
	),
)

result := {
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
