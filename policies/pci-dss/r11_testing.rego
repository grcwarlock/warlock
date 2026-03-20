package pci_dss.r11

import rego.v1

# PCI DSS 4.0 Requirement 11: Test Security of Systems and Networks Regularly

deny_no_vuln_scan contains msg if {
	input.normalized_data.vulnerability_scanning.last_scan_days_ago > 90
	msg := sprintf("R11.3: Last vulnerability scan was %d days ago (requires quarterly)", [input.normalized_data.vulnerability_scanning.last_scan_days_ago])
}

deny_critical_unresolved contains msg if {
	some vuln in input.normalized_data.vulnerability_scanning.critical_findings
	not vuln.remediated
	msg := sprintf("R11.3: Critical vulnerability '%s' unresolved from scan", [vuln.title])
}

deny_no_ids contains msg if {
	not input.normalized_data.intrusion_detection.enabled
	msg := "R11.5: No intrusion detection/prevention system deployed"
}

default compliant := false

compliant if {
	count(deny_no_vuln_scan) == 0
	count(deny_critical_unresolved) == 0
	count(deny_no_ids) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_vuln_scan],
		[f | some f in deny_critical_unresolved],
	),
	[f | some f in deny_no_ids],
)

result := {
	"control_id": "R11",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
