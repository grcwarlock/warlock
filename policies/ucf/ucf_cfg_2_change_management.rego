package ucf.cfg.ucf_cfg_2

import rego.v1

# UCF-CFG-2: Change Management
# Validates that changes go through proper approval processes

deny_low_approval_rate contains msg if {
	input.normalized_data.change_management.total_changes > 0
	input.normalized_data.change_management.approval_rate < 0.95
	msg := sprintf("UCF-CFG-2: Change approval rate is %.0f%% (require 95%%+)", [input.normalized_data.change_management.approval_rate * 100])
}

deny_no_change_data contains msg if {
	not input.normalized_data.change_management.total_changes
	msg := "UCF-CFG-2: No change management data available"
}

deny_no_change_data contains msg if {
	input.normalized_data.change_management.total_changes == 0
	msg := "UCF-CFG-2: No change management data available"
}

default compliant := false

compliant if {
	count(deny_low_approval_rate) == 0
	count(deny_no_change_data) == 0
}

findings := array.concat(
	[f | some f in deny_low_approval_rate],
	[f | some f in deny_no_change_data],
)

result := {
	"control_id": "UCF-CFG-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
