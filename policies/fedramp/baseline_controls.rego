package warlock.fedramp

import rego.v1

# FedRAMP Baseline Controls
# Federal Risk and Authorization Management Program security requirements

# AC-2: Account management — automated account lifecycle
deny_no_account_management contains msg if {
	not input.normalized_data.account_management.automated_lifecycle
	msg := "AC-2: No automated account lifecycle management for FedRAMP boundary"
}

# AU-2: Audit events — required events captured
deny_insufficient_audit contains msg if {
	required_events := {"login", "logout", "access_denied", "privilege_change", "data_access"}
	captured := {e | some e in input.normalized_data.audit.captured_events}
	missing := required_events - captured
	count(missing) > 0
	msg := sprintf("AU-2: Missing required FedRAMP audit events: %v", [missing])
}

# RA-5: Vulnerability scanning — continuous monitoring
deny_no_vuln_scanning contains msg if {
	not input.normalized_data.vulnerability_management.continuous_scanning_enabled
	msg := "RA-5: Continuous vulnerability scanning not enabled within FedRAMP boundary"
}

# SC-7: Boundary protection — network segmentation
deny_no_boundary_protection contains msg if {
	not input.normalized_data.network.boundary_protection_enabled
	msg := "SC-7: No boundary protection — FedRAMP system boundary not enforced"
}

# CA-7: Continuous monitoring — ongoing security assessment
deny_no_continuous_monitoring contains msg if {
	not input.normalized_data.monitoring.continuous_monitoring_plan
	msg := "CA-7: No continuous monitoring plan — FedRAMP requires ongoing assessment"
}

default compliant := false

compliant if {
	count(deny_no_account_management) == 0
	count(deny_insufficient_audit) == 0
	count(deny_no_vuln_scanning) == 0
	count(deny_no_boundary_protection) == 0
	count(deny_no_continuous_monitoring) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_account_management],
		[f | some f in deny_insufficient_audit],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_vuln_scanning],
			[f | some f in deny_no_boundary_protection],
		),
		[f | some f in deny_no_continuous_monitoring],
	),
)

result := {
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
