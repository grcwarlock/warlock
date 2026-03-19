package cmmc.au.au_l2_3_3_2

import rego.v1

# AU.L2-3.3.2: Audit Review, Analysis, and Reporting
# Ensure audit records are reviewed and analyzed for indications of unlawful or unauthorized activity

deny_no_log_monitoring contains msg if {
	some system in input.normalized_data.systems
	system.audit_logging_enabled
	not system.log_monitoring_enabled
	msg := sprintf("AU.L2-3.3.2: System '%s' has audit logging but no active log monitoring or analysis", [system.name])
}

deny_no_alerting contains msg if {
	some system in input.normalized_data.systems
	system.audit_logging_enabled
	not system.security_alerting_configured
	msg := sprintf("AU.L2-3.3.2: System '%s' does not have security alerting configured for anomalous events", [system.name])
}

deny_no_siem_integration contains msg if {
	some system in input.normalized_data.systems
	system.processes_cui
	not system.siem_integrated
	msg := sprintf("AU.L2-3.3.2: CUI system '%s' is not integrated with SIEM for centralized audit review", [system.name])
}

default compliant := false

compliant if {
	count(deny_no_log_monitoring) == 0
	count(deny_no_alerting) == 0
	count(deny_no_siem_integration) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_log_monitoring],
		[f | some f in deny_no_alerting],
	),
	[f | some f in deny_no_siem_integration],
)

result := {
	"control_id": "AU.L2-3.3.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
