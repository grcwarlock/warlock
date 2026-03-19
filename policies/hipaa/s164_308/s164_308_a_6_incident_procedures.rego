package hipaa.s164_308.s164_308_a_6

import rego.v1

# 164.308(a)(6): Security Incident Procedures
# Requires policies and procedures to address security incidents
# including identification, response, mitigation, and documentation

deny_no_incident_response_plan contains msg if {
	not input.normalized_data.policies.incident_response_plan
	msg := "164.308(a)(6): No security incident response plan exists"
}

deny_no_incident_logging contains msg if {
	not input.normalized_data.config.security_incident_logging_enabled
	msg := "164.308(a)(6): Security incident logging is not enabled — must be able to identify and respond to suspected or known incidents"
}

deny_no_breach_notification_procedure contains msg if {
	not input.normalized_data.policies.breach_notification_procedure
	msg := "164.308(a)(6): No breach notification procedure — must document process for reporting breaches of unsecured ePHI"
}

default compliant := false

compliant if {
	count(deny_no_incident_response_plan) == 0
	count(deny_no_incident_logging) == 0
	count(deny_no_breach_notification_procedure) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_incident_response_plan],
		[f | some f in deny_no_incident_logging],
	),
	[f | some f in deny_no_breach_notification_procedure],
)

result := {
	"control_id": "164.308(a)(6)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
