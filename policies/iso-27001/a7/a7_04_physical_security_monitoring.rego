package iso_27001.a7.a7_04

import rego.v1

# A.7.4: Physical Security Monitoring
# Validates continuous monitoring of access patterns and anomaly detection

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.7.4: GuardDuty is not enabled for continuous access monitoring"
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.7.4: Security Hub is not enabled for centralized security monitoring"
}

deny_no_vpc_flow_logs contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.flow_logs_enabled
	msg := sprintf("A.7.4: VPC '%s' does not have flow logs enabled for network monitoring", [vpc.id])
}

deny_no_security_dashboard contains msg if {
	not input.normalized_data.cloudwatch.security_monitoring_dashboard_exists
	msg := "A.7.4: No CloudWatch security monitoring dashboard configured"
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_security_hub) == 0
	count(deny_no_vpc_flow_logs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_vpc_flow_logs],
		[f | some f in deny_no_security_dashboard],
	),
)

result := {
	"control_id": "A.7.4",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
