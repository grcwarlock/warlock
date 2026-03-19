package cmmc.au.au_l2_3_3_1

import rego.v1

# AU.L2-3.3.1: System-Level Auditing
# Create and retain system audit logs and records to enable monitoring, analysis, investigation, and reporting

deny_no_audit_logging contains msg if {
	some system in input.normalized_data.systems
	not system.audit_logging_enabled
	msg := sprintf("AU.L2-3.3.1: System '%s' does not have audit logging enabled", [system.name])
}

deny_insufficient_retention contains msg if {
	some system in input.normalized_data.systems
	system.audit_logging_enabled
	system.log_retention_days < 90
	msg := sprintf("AU.L2-3.3.1: System '%s' retains audit logs for only %d days — minimum 90 days required", [system.name, system.log_retention_days])
}

deny_no_cloudtrail contains msg if {
	some account in input.normalized_data.accounts
	not account.cloudtrail_enabled
	msg := sprintf("AU.L2-3.3.1: Account '%s' does not have CloudTrail or equivalent audit trail enabled", [account.name])
}

deny_no_log_integrity contains msg if {
	some system in input.normalized_data.systems
	system.audit_logging_enabled
	not system.log_integrity_validation
	msg := sprintf("AU.L2-3.3.1: System '%s' does not validate audit log integrity — tamper detection required", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_audit_logging) == 0
	count(deny_insufficient_retention) == 0
	count(deny_no_cloudtrail) == 0
	count(deny_no_log_integrity) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_audit_logging],
		[f | some f in deny_insufficient_retention],
	),
	array.concat(
		[f | some f in deny_no_cloudtrail],
		[f | some f in deny_no_log_integrity],
	),
)

result := {
	"control_id": "AU.L2-3.3.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
