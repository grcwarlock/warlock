package ucf.rsk.ucf_rsk_4

import rego.v1

# UCF-RSK-4: Risk Monitoring
# Validates continuous monitoring tools are enabled

deny_no_config contains msg if {
	not input.normalized_data.config.enabled
	msg := "UCF-RSK-4: AWS Config is not enabled for continuous monitoring"
}

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty_enabled
	msg := "UCF-RSK-4: GuardDuty threat detection is not enabled"
}

default compliant := false

compliant if {
	count(deny_no_config) == 0
	count(deny_no_guardduty) == 0
}

findings := array.concat(
	[f | some f in deny_no_config],
	[f | some f in deny_no_guardduty],
)

result := {
	"control_id": "UCF-RSK-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
