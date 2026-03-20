package pci_dss.r10

import rego.v1

# PCI DSS 4.0 Requirement 10: Log and Monitor All Access

deny_no_audit_trail contains msg if {
	not input.normalized_data.audit_logging.enabled
	msg := "R10.1: Audit logging is not enabled for CDE systems"
}

deny_no_log_review contains msg if {
	input.normalized_data.audit_logging.enabled
	not input.normalized_data.audit_logging.automated_review
	msg := "R10.4: No automated audit log review mechanism in place"
}

deny_insufficient_retention contains msg if {
	input.normalized_data.audit_logging.enabled
	input.normalized_data.audit_logging.retention_days < 365
	msg := sprintf("R10.5: Audit log retention is %d days (requires 365+)", [input.normalized_data.audit_logging.retention_days])
}

default compliant := false

compliant if {
	count(deny_no_audit_trail) == 0
	count(deny_no_log_review) == 0
	count(deny_insufficient_retention) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_audit_trail],
		[f | some f in deny_no_log_review],
	),
	[f | some f in deny_insufficient_retention],
)

result := {
	"control_id": "R10",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
