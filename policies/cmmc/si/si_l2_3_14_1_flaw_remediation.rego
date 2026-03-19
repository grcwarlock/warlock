package cmmc.si.si_l2_3_14_1

import rego.v1

# SI.L2-3.14.1: Flaw Remediation
# Identify, report, and correct system flaws in a timely manner

deny_critical_vulnerabilities contains msg if {
	some vuln in input.normalized_data.vulnerabilities
	vuln.severity == "critical"
	vuln.age_days > 15
	msg := sprintf("SI.L2-3.14.1: Critical vulnerability '%s' on '%s' has been unpatched for %d days — 15-day SLA exceeded", [vuln.cve_id, vuln.system_name, vuln.age_days])
}

deny_high_vulnerabilities contains msg if {
	some vuln in input.normalized_data.vulnerabilities
	vuln.severity == "high"
	vuln.age_days > 30
	msg := sprintf("SI.L2-3.14.1: High vulnerability '%s' on '%s' has been unpatched for %d days — 30-day SLA exceeded", [vuln.cve_id, vuln.system_name, vuln.age_days])
}

deny_no_patch_management contains msg if {
	some system in input.normalized_data.systems
	not system.patch_management_enabled
	msg := sprintf("SI.L2-3.14.1: System '%s' does not have automated patch management enabled", [system.name])
}

default compliant := false

compliant if {
	count(deny_critical_vulnerabilities) == 0
	count(deny_high_vulnerabilities) == 0
	count(deny_no_patch_management) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_critical_vulnerabilities],
		[f | some f in deny_high_vulnerabilities],
	),
	[f | some f in deny_no_patch_management],
)

result := {
	"control_id": "SI.L2-3.14.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
