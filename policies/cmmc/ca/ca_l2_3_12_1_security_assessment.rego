package cmmc.ca.ca_l2_3_12_1

import rego.v1

# CA.L2-3.12.1: Security Assessment
# Periodically assess the security controls in organizational systems to determine if the controls are effective

deny_no_security_assessment contains msg if {
	some system in input.normalized_data.systems
	not system.security_assessment_completed
	msg := sprintf("CA.L2-3.12.1: System '%s' has not undergone a security assessment", [system.name])
}

deny_stale_assessment contains msg if {
	some system in input.normalized_data.systems
	system.security_assessment_completed
	system.assessment_age_days > 365
	msg := sprintf("CA.L2-3.12.1: System '%s' security assessment is %d days old — annual reassessment required", [system.name, system.assessment_age_days])
}

deny_open_poams contains msg if {
	some poam in input.normalized_data.poams
	poam.status == "open"
	poam.overdue
	msg := sprintf("CA.L2-3.12.1: POA&M item '%s' is overdue — remediation deadline has passed", [poam.id])
}

default compliant := false

compliant if {
	count(deny_no_security_assessment) == 0
	count(deny_stale_assessment) == 0
	count(deny_open_poams) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_assessment],
		[f | some f in deny_stale_assessment],
	),
	[f | some f in deny_open_poams],
)

result := {
	"control_id": "CA.L2-3.12.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
