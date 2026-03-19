package nist.ca.ca_7

import rego.v1

# CA-7: Continuous Monitoring
# Validates continuous monitoring strategy and implementation

deny_no_monitoring_strategy contains msg if {
	not input.normalized_data.continuous_monitoring
	msg := "CA-7: No continuous monitoring strategy configured"
}

deny_no_vulnerability_scanning contains msg if {
	input.normalized_data.continuous_monitoring
	not input.normalized_data.continuous_monitoring.vulnerability_scanning_enabled
	msg := "CA-7: Vulnerability scanning is not enabled as part of continuous monitoring"
}

deny_scan_frequency_insufficient contains msg if {
	input.normalized_data.continuous_monitoring
	input.normalized_data.continuous_monitoring.vulnerability_scanning_enabled
	input.normalized_data.continuous_monitoring.last_vulnerability_scan_days > 30
	msg := sprintf("CA-7: Last vulnerability scan was %d days ago (exceeds 30-day requirement)", [input.normalized_data.continuous_monitoring.last_vulnerability_scan_days])
}

deny_no_config_monitoring contains msg if {
	input.provider == "aws"
	not input.normalized_data.continuous_monitoring.aws_config_enabled
	msg := "CA-7: AWS Config is not enabled for configuration monitoring"
}

deny_no_config_monitoring contains msg if {
	input.provider == "azure"
	not input.normalized_data.continuous_monitoring.azure_policy_enabled
	msg := "CA-7: Azure Policy is not enabled for configuration monitoring"
}

deny_no_security_hub contains msg if {
	input.provider == "aws"
	not input.normalized_data.continuous_monitoring.security_hub_enabled
	msg := "CA-7: AWS Security Hub is not enabled for centralized security monitoring"
}

deny_no_monitoring_reporting contains msg if {
	input.normalized_data.continuous_monitoring
	not input.normalized_data.continuous_monitoring.reporting_configured
	msg := "CA-7: Continuous monitoring reporting to authorizing official is not configured"
}

deny_no_automated_alerting contains msg if {
	input.normalized_data.continuous_monitoring
	not input.normalized_data.continuous_monitoring.automated_alerting
	msg := "CA-7: Automated security alerting is not configured for continuous monitoring"
}

default compliant := false

compliant if {
	count(deny_no_monitoring_strategy) == 0
	count(deny_no_vulnerability_scanning) == 0
	count(deny_scan_frequency_insufficient) == 0
	count(deny_no_monitoring_reporting) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_monitoring_strategy],
		[f | some f in deny_no_vulnerability_scanning],
	),
	array.concat(
		[f | some f in deny_scan_frequency_insufficient],
		array.concat(
			[f | some f in deny_no_config_monitoring],
			array.concat(
				[f | some f in deny_no_security_hub],
				array.concat(
					[f | some f in deny_no_monitoring_reporting],
					[f | some f in deny_no_automated_alerting],
				),
			),
		),
	),
)

result := {
	"control_id": "CA-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
