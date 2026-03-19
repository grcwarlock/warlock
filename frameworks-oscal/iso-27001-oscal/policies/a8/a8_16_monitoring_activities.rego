package iso_27001.a8.a8_16

import rego.v1

# A.8.16: Monitoring Activities
# Validates anomaly detection and monitoring are configured

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.8.16: GuardDuty is not enabled for anomaly detection"
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.8.16: Security Hub is not enabled for centralized monitoring"
}

deny_no_anomaly_detection contains msg if {
	not input.normalized_data.cloudwatch.anomaly_detectors_configured
	msg := "A.8.16: No CloudWatch anomaly detectors configured for behavioral monitoring"
}

deny_high_severity_findings contains msg if {
	input.normalized_data.guardduty.enabled
	input.normalized_data.guardduty.high_severity_finding_count > 0
	msg := sprintf("A.8.16: %d high-severity GuardDuty findings require investigation", [input.normalized_data.guardduty.high_severity_finding_count])
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_security_hub) == 0
	count(deny_high_severity_findings) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_anomaly_detection],
		[f | some f in deny_high_severity_findings],
	),
)

result := {
	"control_id": "A.8.16",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
