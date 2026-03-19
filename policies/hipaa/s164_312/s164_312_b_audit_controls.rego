package hipaa.s164_312.s164_312_b

import rego.v1

# 164.312(b): Audit Controls
# Requires mechanisms to record and examine activity in systems
# containing or using ePHI

deny_no_audit_logging contains msg if {
	not input.normalized_data.config.audit_logging_enabled
	msg := "164.312(b): Audit logging is not enabled — must implement hardware, software, or procedural mechanisms to record access to ePHI"
}

deny_insufficient_log_retention contains msg if {
	input.normalized_data.config.audit_logging_enabled
	input.normalized_data.config.log_retention_days < 365
	msg := sprintf("164.312(b): Audit log retention is %d days — must retain logs for at least 365 days", [input.normalized_data.config.log_retention_days])
}

deny_no_log_monitoring contains msg if {
	input.normalized_data.config.audit_logging_enabled
	not input.normalized_data.config.log_monitoring_enabled
	msg := "164.312(b): Audit log monitoring is not enabled — must regularly review records of system activity"
}

deny_resource_no_logging contains msg if {
	some resource in input.normalized_data.resources.datastores
	resource.contains_ephi
	not resource.audit_logging_enabled
	msg := sprintf("164.312(b): Datastore '%s' containing ePHI does not have audit logging enabled", [resource.name])
}

default compliant := false

compliant if {
	count(deny_no_audit_logging) == 0
	count(deny_insufficient_log_retention) == 0
	count(deny_no_log_monitoring) == 0
	count(deny_resource_no_logging) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_audit_logging],
		[f | some f in deny_insufficient_log_retention],
	),
	array.concat(
		[f | some f in deny_no_log_monitoring],
		[f | some f in deny_resource_no_logging],
	),
)

result := {
	"control_id": "164.312(b)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
