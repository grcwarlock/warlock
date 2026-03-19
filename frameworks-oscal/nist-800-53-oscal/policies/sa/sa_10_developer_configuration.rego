package nist.sa.sa_10

import rego.v1

# SA-10: Developer Configuration Management

deny_no_config_management contains msg if {
	not input.normalized_data.developer_config_management
	msg := "SA-10: No developer configuration management process established"
}

deny_no_version_control contains msg if {
	dcm := input.normalized_data.developer_config_management
	not dcm.version_control_used
	msg := "SA-10: Version control not used for system development"
}

deny_no_change_tracking contains msg if {
	dcm := input.normalized_data.developer_config_management
	not dcm.change_tracking_enabled
	msg := "SA-10: Change tracking not enabled for system components"
}

deny_no_integrity_verification contains msg if {
	dcm := input.normalized_data.developer_config_management
	not dcm.integrity_verification
	msg := "SA-10: No integrity verification mechanism for configuration items"
}

deny_no_baseline contains msg if {
	dcm := input.normalized_data.developer_config_management
	not dcm.configuration_baseline_established
	msg := "SA-10: No configuration baseline established for development"
}

default compliant := false

compliant if {
	count(deny_no_config_management) == 0
	count(deny_no_version_control) == 0
	count(deny_no_change_tracking) == 0
	count(deny_no_integrity_verification) == 0
	count(deny_no_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_config_management],
		[f | some f in deny_no_version_control],
	),
	array.concat(
		[f | some f in deny_no_change_tracking],
		array.concat(
			[f | some f in deny_no_integrity_verification],
			[f | some f in deny_no_baseline],
		),
	),
)

result := {
	"control_id": "SA-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
