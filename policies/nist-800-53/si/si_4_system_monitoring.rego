package nist.si.si_4

import rego.v1

# SI-4: System Monitoring

deny_no_ids contains msg if {
	input.provider == "aws"
	not input.normalized_data.guardduty_enabled
	msg := "SI-4: No intrusion detection service enabled (GuardDuty)"
}

deny_no_centralized_monitoring contains msg if {
	input.provider == "aws"
	not input.normalized_data.security_hub_enabled
	msg := "SI-4: No centralized security monitoring (Security Hub)"
}

deny_no_monitoring_azure contains msg if {
	input.provider == "azure"
	not input.normalized_data.defender_enabled
	msg := "SI-4: Microsoft Defender for Cloud not enabled"
}

deny_no_monitoring_gcp contains msg if {
	input.provider == "gcp"
	not input.normalized_data.scc_enabled
	msg := "SI-4: Security Command Center not enabled"
}

default compliant := false

compliant if {
	count(deny_no_ids) == 0
	count(deny_no_centralized_monitoring) == 0
	count(deny_no_monitoring_azure) == 0
	count(deny_no_monitoring_gcp) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ids],
		[f | some f in deny_no_centralized_monitoring],
	),
	array.concat(
		[f | some f in deny_no_monitoring_azure],
		[f | some f in deny_no_monitoring_gcp],
	),
)

result := {
	"control_id": "SI-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
