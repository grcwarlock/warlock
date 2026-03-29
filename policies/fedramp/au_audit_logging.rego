package warlock.fedramp.au

import rego.v1

# FedRAMP Audit and Accountability Requirements

# AU-3: Content of audit records — sufficient detail
deny_insufficient_audit_detail contains msg if {
	some record in input.normalized_data.audit.sample_records
	not record.timestamp
	msg := sprintf("AU-3: Audit record '%s' missing timestamp", [record.id])
}

deny_no_user_identity contains msg if {
	some record in input.normalized_data.audit.sample_records
	not record.user_identity
	msg := sprintf("AU-3: Audit record '%s' missing user identity", [record.id])
}

# AU-6: Audit review — regular analysis of audit records
deny_no_audit_review contains msg if {
	not input.normalized_data.audit.regular_review_enabled
	msg := "AU-6: No regular audit log review process — FedRAMP requires weekly review"
}

# AU-8: Time stamps — synchronized to authoritative source
deny_no_time_sync contains msg if {
	not input.normalized_data.audit.time_synchronization_enabled
	msg := "AU-8: Audit time stamps not synchronized to authoritative time source"
}

# AU-9: Protection of audit information — tamper protection
deny_no_audit_protection contains msg if {
	not input.normalized_data.audit.tamper_protection_enabled
	msg := "AU-9: Audit records not protected against unauthorized access or modification"
}

# AU-11: Audit record retention — 1 year minimum for FedRAMP Moderate
deny_insufficient_retention contains msg if {
	input.normalized_data.audit.retention_days < 365
	msg := sprintf("AU-11: Audit retention %d days — FedRAMP Moderate requires 365 days minimum", [input.normalized_data.audit.retention_days])
}

default compliant := false

compliant if {
	count(deny_insufficient_audit_detail) == 0
	count(deny_no_user_identity) == 0
	count(deny_no_audit_review) == 0
	count(deny_no_time_sync) == 0
	count(deny_no_audit_protection) == 0
	count(deny_insufficient_retention) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_insufficient_audit_detail],
			[f | some f in deny_no_user_identity],
		),
		[f | some f in deny_no_audit_review],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_time_sync],
			[f | some f in deny_no_audit_protection],
		),
		[f | some f in deny_insufficient_retention],
	),
)

result := {
	"control_id": "AU",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
