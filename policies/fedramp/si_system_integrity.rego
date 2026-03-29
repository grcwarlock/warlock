package warlock.fedramp.si

import rego.v1

# FedRAMP System and Information Integrity

# SI-2: Flaw remediation — patch within FedRAMP-defined timeframes
deny_overdue_patches contains msg if {
	some vuln in input.normalized_data.vulnerabilities
	vuln.severity == "critical"
	vuln.days_since_discovery > 30
	not vuln.remediated
	msg := sprintf("SI-2: Critical vulnerability '%s' unpatched for %d days (30-day SLA)", [vuln.id, vuln.days_since_discovery])
}

deny_overdue_high_patches contains msg if {
	some vuln in input.normalized_data.vulnerabilities
	vuln.severity == "high"
	vuln.days_since_discovery > 90
	not vuln.remediated
	msg := sprintf("SI-2: High vulnerability '%s' unpatched for %d days (90-day SLA)", [vuln.id, vuln.days_since_discovery])
}

# SI-3: Malicious code protection
deny_no_malware_protection contains msg if {
	not input.normalized_data.endpoint_protection.malware_scanning_enabled
	msg := "SI-3: Malicious code protection not enabled on endpoints"
}

# SI-4: Information system monitoring
deny_no_system_monitoring contains msg if {
	not input.normalized_data.monitoring.system_monitoring_enabled
	msg := "SI-4: Information system monitoring not enabled — cannot detect attacks"
}

# SI-5: Security alerts and advisories — process to receive and act on
deny_no_advisory_process contains msg if {
	not input.normalized_data.vulnerability_management.advisory_monitoring_enabled
	msg := "SI-5: No process for receiving security alerts and advisories"
}

default compliant := false

compliant if {
	count(deny_overdue_patches) == 0
	count(deny_overdue_high_patches) == 0
	count(deny_no_malware_protection) == 0
	count(deny_no_system_monitoring) == 0
	count(deny_no_advisory_process) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_overdue_patches],
		[f | some f in deny_overdue_high_patches],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_malware_protection],
			[f | some f in deny_no_system_monitoring],
		),
		[f | some f in deny_no_advisory_process],
	),
)

result := {
	"control_id": "SI",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
