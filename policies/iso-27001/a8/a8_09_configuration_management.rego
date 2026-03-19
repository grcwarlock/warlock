package iso_27001.a8.a8_09

import rego.v1

# A.8.9: Configuration Management
# Validates configuration management and drift detection

deny_no_config_recorder contains msg if {
	not input.normalized_data.config.recorder_enabled
	msg := "A.8.9: AWS Config recorder is not enabled for configuration tracking"
}

deny_config_not_recording contains msg if {
	input.normalized_data.config.recorder_enabled
	not input.normalized_data.config.is_recording
	msg := "A.8.9: AWS Config recorder exists but is not actively recording"
}

deny_noncompliant_rules contains msg if {
	noncompliant := [r | some r in input.normalized_data.config.rules; r.compliance_type != "COMPLIANT"]
	count(noncompliant) > 0
	msg := sprintf("A.8.9: %d AWS Config rules are non-compliant — configuration drift detected", [count(noncompliant)])
}

deny_no_conformance_pack contains msg if {
	not input.normalized_data.config.conformance_packs_exist
	msg := "A.8.9: No conformance packs deployed for configuration baseline enforcement"
}

default compliant := false

compliant if {
	count(deny_no_config_recorder) == 0
	count(deny_config_not_recording) == 0
	count(deny_noncompliant_rules) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_config_recorder],
		[f | some f in deny_config_not_recording],
	),
	array.concat(
		[f | some f in deny_noncompliant_rules],
		[f | some f in deny_no_conformance_pack],
	),
)

result := {
	"control_id": "A.8.9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
