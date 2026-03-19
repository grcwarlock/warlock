package nist.au.au_6

import rego.v1

# AU-6: Audit Record Review, Analysis, and Reporting

deny_no_guardduty contains msg if {
	input.provider == "aws"
	not input.normalized_data.guardduty_enabled
	msg := "AU-6: GuardDuty is not enabled — no automated threat detection"
}

deny_no_security_hub contains msg if {
	input.provider == "aws"
	not input.normalized_data.security_hub_enabled
	msg := "AU-6: Security Hub is not enabled — no centralized findings aggregation"
}

deny_no_defender contains msg if {
	input.provider == "azure"
	not input.normalized_data.defender_enabled
	msg := "AU-6: Microsoft Defender for Cloud is not enabled"
}

deny_no_scc contains msg if {
	input.provider == "gcp"
	not input.normalized_data.scc_enabled
	msg := "AU-6: Security Command Center is not enabled"
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_security_hub) == 0
	count(deny_no_defender) == 0
	count(deny_no_scc) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_defender],
		[f | some f in deny_no_scc],
	),
)

result := {
	"control_id": "AU-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
