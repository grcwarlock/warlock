package pci_dss.r6

import rego.v1

# PCI DSS 4.0 Requirement 6: Develop and Maintain Secure Systems and Software

deny_critical_vulns contains msg if {
	some vuln in input.normalized_data.vulnerabilities
	vuln.severity in {"critical", "high"}
	not vuln.remediated
	msg := sprintf("R6.3: %s vulnerability '%s' is unresolved on %s", [vuln.severity, vuln.title, vuln.host])
}

deny_unapproved_changes contains msg if {
	some change in input.normalized_data.changes
	change.environment == "production"
	not change.approved
	msg := sprintf("R6.5: Change '%s' deployed to production without approval", [change.id])
}

default compliant := false

compliant if {
	count(deny_critical_vulns) == 0
	count(deny_unapproved_changes) == 0
}

findings := array.concat(
	[f | some f in deny_critical_vulns],
	[f | some f in deny_unapproved_changes],
)

result := {
	"control_id": "R6",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
