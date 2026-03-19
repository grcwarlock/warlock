package nist.pl.pl_7

import rego.v1

# PL-7: Privacy Impact Assessment

deny_no_pia contains msg if {
	some system in input.normalized_data.planning.systems
	system.processes_pii
	not system.pia_conducted
	msg := sprintf("PL-7: System '%s' processes PII but has not had a Privacy Impact Assessment (PIA) conducted", [system.system_id])
}

deny_pia_not_current contains msg if {
	some system in input.normalized_data.planning.systems
	system.processes_pii
	system.pia_conducted
	not system.pia_reviewed_within_365_days
	msg := sprintf("PL-7: Privacy Impact Assessment for system '%s' has not been reviewed within the last 365 days", [system.system_id])
}

deny_no_dpia contains msg if {
	some system in input.normalized_data.planning.systems
	system.high_risk_processing
	not system.dpia_conducted
	msg := sprintf("PL-7: System '%s' performs high-risk data processing but has not had a Data Protection Impact Assessment (DPIA)", [system.system_id])
}

deny_pia_not_published contains msg if {
	some system in input.normalized_data.planning.systems
	system.processes_pii
	system.pia_conducted
	not system.pia_publicly_available
	msg := sprintf("PL-7: PIA for system '%s' is not publicly available as required", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_no_pia) == 0
	count(deny_pia_not_current) == 0
	count(deny_no_dpia) == 0
	count(deny_pia_not_published) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_pia],
		[f | some f in deny_pia_not_current],
	),
	array.concat(
		[f | some f in deny_no_dpia],
		[f | some f in deny_pia_not_published],
	),
)

result := {
	"control_id": "PL-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
