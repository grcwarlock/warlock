package warlock.iso_27701.breach

import rego.v1

# ISO 27701 Breach Notification Controls
# 7.3.8, A.7.3.8, B.8.5.5: PII breach notification

# Breach notification process established
deny_no_breach_process contains msg if {
	not input.normalized_data.privacy.breach_notification_process
	msg := "A.7.3.8: No PII breach notification process established"
}

# Breach notification within required timeframe (72 hours)
deny_late_notification contains msg if {
	some breach in input.normalized_data.privacy.breaches
	not breach.notification_sent
	breach.hours_since_discovery > 72
	msg := sprintf("A.7.3.8: PII breach '%s' not notified within 72 hours (%d hours elapsed)", [breach.id, breach.hours_since_discovery])
}

# Breach records maintained
deny_no_breach_records contains msg if {
	not input.normalized_data.privacy.breach_records_maintained
	msg := "B.8.5.5: Breach records not maintained — cannot demonstrate notification compliance"
}

# Breach impact assessment performed
deny_no_impact_assessment contains msg if {
	some breach in input.normalized_data.privacy.breaches
	not breach.impact_assessed
	msg := sprintf("A.7.3.8: PII breach '%s' — impact assessment not performed", [breach.id])
}

default compliant := false

compliant if {
	count(deny_no_breach_process) == 0
	count(deny_late_notification) == 0
	count(deny_no_breach_records) == 0
	count(deny_no_impact_assessment) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_breach_process],
		[f | some f in deny_late_notification],
	),
	array.concat(
		[f | some f in deny_no_breach_records],
		[f | some f in deny_no_impact_assessment],
	),
)

result := {
	"control_id": "A.7.3.8",
	"framework": "ISO 27701",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
