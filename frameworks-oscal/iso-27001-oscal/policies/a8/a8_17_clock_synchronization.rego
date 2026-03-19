package iso_27001.a8.a8_17

import rego.v1

# A.8.17: Clock Synchronization
# Validates NTP synchronization across all instances

deny_instances_no_ssm contains msg if {
	some instance in input.normalized_data.ec2.instances
	instance.state == "running"
	not instance.ssm_managed
	msg := sprintf("A.8.17: Instance '%s' is not SSM-managed — NTP sync cannot be verified", [instance.id])
}

deny_no_ntp_check contains msg if {
	not input.normalized_data.ssm.ntp_check_commands_executed
	msg := "A.8.17: No SSM commands have been run to verify NTP synchronization"
}

deny_no_ntp_config_document contains msg if {
	not input.normalized_data.ssm.ntp_config_document_exists
	msg := "A.8.17: No SSM document for NTP configuration standardization"
}

deny_cloudtrail_timestamp_inconsistency contains msg if {
	input.normalized_data.cloudtrail.timestamp_inconsistencies_detected
	msg := "A.8.17: CloudTrail events show timestamp inconsistencies — clock sync issue"
}

default compliant := false

compliant if {
	count(deny_instances_no_ssm) == 0
	count(deny_no_ntp_check) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_instances_no_ssm],
		[f | some f in deny_no_ntp_check],
	),
	array.concat(
		[f | some f in deny_no_ntp_config_document],
		[f | some f in deny_cloudtrail_timestamp_inconsistency],
	),
)

result := {
	"control_id": "A.8.17",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
