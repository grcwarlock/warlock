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

# CC7.3: Change detection mechanisms
deny_no_fim contains msg if {
	not input.normalized_data.file_integrity_monitoring_enabled
	msg := "CC7.3: No file integrity monitoring — unauthorized changes to critical files not detected"
}

# CC7.4: Incident response procedures
deny_no_incident_response contains msg if {
	not input.normalized_data.incident_response.plan_documented
	msg := "CC7.4: No incident response plan documented"
}

# CC7.5: Root cause analysis and remediation
deny_no_root_cause_process contains msg if {
	not input.normalized_data.incident_response.root_cause_analysis_required
	msg := "CC7.5: No root cause analysis requirement — incidents may recur without remediation"
}

all_findings := array.concat(
	findings,
	array.concat(
		[f | some f in deny_no_fim],
		array.concat(
			[f | some f in deny_no_incident_response],
			[f | some f in deny_no_root_cause_process],
		),
	),
)

result := {
	"control_id": "CC7",
	"framework": "SOC 2",
	"compliant": compliant,
	"sub_controls": {
		"CC7.1": count(deny_no_monitoring) == 0,
		"CC7.2": count(deny_no_audit_trail) == 0,
		"CC7.3": count(deny_no_fim) == 0,
		"CC7.4": count(deny_no_incident_response) == 0,
		"CC7.5": count(deny_no_root_cause_process) == 0,
	},
	"findings": all_findings,
	"severity": "high",
}
