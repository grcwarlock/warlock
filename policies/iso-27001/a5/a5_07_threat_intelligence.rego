package iso_27001.a5.a5_07

import rego.v1

# A.5.7: Threat Intelligence
# Validates threat intelligence collection and analysis is operational

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.5.7: GuardDuty is not enabled — no automated threat detection in place"
}

deny_no_threat_intel_sets contains msg if {
	input.normalized_data.guardduty.enabled
	count(input.normalized_data.guardduty.threat_intel_sets) == 0
	msg := "A.5.7: No custom threat intelligence sets configured in GuardDuty"
}

deny_guardduty_low_frequency contains msg if {
	input.normalized_data.guardduty.enabled
	input.normalized_data.guardduty.finding_publishing_frequency != "FIFTEEN_MINUTES"
	msg := sprintf("A.5.7: GuardDuty finding frequency is '%s' — should be FIFTEEN_MINUTES for timely threat intel", [input.normalized_data.guardduty.finding_publishing_frequency])
}

deny_high_severity_findings contains msg if {
	input.normalized_data.guardduty.enabled
	input.normalized_data.guardduty.high_severity_finding_count > 0
	msg := sprintf("A.5.7: %d high-severity GuardDuty findings require immediate investigation", [input.normalized_data.guardduty.high_severity_finding_count])
}

deny_no_malware_protection contains msg if {
	input.normalized_data.guardduty.enabled
	not input.normalized_data.guardduty.malware_protection_enabled
	msg := "A.5.7: GuardDuty Malware Protection is not enabled"
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_threat_intel_sets) == 0
	count(deny_high_severity_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_threat_intel_sets],
	),
	array.concat(
		[f | some f in deny_guardduty_low_frequency],
		array.concat(
			[f | some f in deny_high_severity_findings],
			[f | some f in deny_no_malware_protection],
		),
	),
)

result := {
	"control_id": "A.5.7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
