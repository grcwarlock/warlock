package soc2.cc7

import rego.v1

# SOC 2 CC7: System Operations — Monitoring and Detection
# Maps to NIST AU-2, AU-6, SI-4

deny_no_monitoring contains msg if {
	input.provider == "aws"
	not input.normalized_data.guardduty_enabled
	not input.normalized_data.security_hub_enabled
	msg := "CC7.1: No monitoring or detection services enabled"
}

deny_no_audit_trail contains msg if {
	input.provider == "aws"
	trails := [t | some t in input.normalized_data.trails; t.is_multi_region; t.is_logging]
	count(trails) == 0
	msg := "CC7.2: No active multi-region audit trail"
}

default compliant := false

compliant if {
	count(deny_no_monitoring) == 0
	count(deny_no_audit_trail) == 0
}

findings := array.concat(
	[f | some f in deny_no_monitoring],
	[f | some f in deny_no_audit_trail],
)

result := {
	"control_id": "CC7",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
