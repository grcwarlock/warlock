package iso_27001.a5.a5_24

import rego.v1

# A.5.24: Information Security Incident Management Planning and Preparation
# Validates incident response plan and automation are in place

deny_no_guardduty contains msg if {
	not input.normalized_data.guardduty.enabled
	msg := "A.5.24: GuardDuty is not enabled for automated incident detection"
}

deny_no_security_hub contains msg if {
	not input.normalized_data.security_hub.enabled
	msg := "A.5.24: Security Hub is not enabled for centralized incident management"
}

deny_no_incident_sns contains msg if {
	not input.normalized_data.sns.security_incident_topic_exists
	msg := "A.5.24: No SNS topic configured for security incident notifications"
}

deny_no_high_severity_alerts contains msg if {
	not input.normalized_data.eventbridge.high_severity_finding_rule_exists
	msg := "A.5.24: No EventBridge rule for high-severity finding notifications"
}

deny_no_ir_playbooks contains msg if {
	not input.normalized_data.ssm.ir_automation_documents_exist
	msg := "A.5.24: No incident response playbooks stored as SSM Automation documents"
}

default compliant := false

compliant if {
	count(deny_no_guardduty) == 0
	count(deny_no_security_hub) == 0
	count(deny_no_incident_sns) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_guardduty],
		[f | some f in deny_no_security_hub],
	),
	array.concat(
		[f | some f in deny_no_incident_sns],
		array.concat(
			[f | some f in deny_no_high_severity_alerts],
			[f | some f in deny_no_ir_playbooks],
		),
	),
)

result := {
	"control_id": "A.5.24",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
