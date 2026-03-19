package nist.sa.sa_9

import rego.v1

# SA-9: External System Services

deny_no_external_services_policy contains msg if {
	not input.normalized_data.external_services_policy
	msg := "SA-9: No policy for external system services established"
}

deny_service_no_agreement contains msg if {
	some service in input.normalized_data.external_services
	not service.service_level_agreement
	msg := sprintf("SA-9: External service '%s' does not have a service level agreement", [service.name])
}

deny_service_no_security_controls contains msg if {
	some service in input.normalized_data.external_services
	not service.security_controls_documented
	msg := sprintf("SA-9: Security controls not documented for external service '%s'", [service.name])
}

deny_service_not_monitored contains msg if {
	some service in input.normalized_data.external_services
	not service.compliance_monitored
	msg := sprintf("SA-9: Compliance not monitored for external service '%s'", [service.name])
}

deny_no_interconnection_agreement contains msg if {
	some service in input.normalized_data.external_services
	service.requires_interconnection
	not service.interconnection_agreement
	msg := sprintf("SA-9: No interconnection security agreement for external service '%s'", [service.name])
}

default compliant := false

compliant if {
	count(deny_no_external_services_policy) == 0
	count(deny_service_no_agreement) == 0
	count(deny_service_no_security_controls) == 0
	count(deny_service_not_monitored) == 0
	count(deny_no_interconnection_agreement) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_external_services_policy],
		[f | some f in deny_service_no_agreement],
	),
	array.concat(
		[f | some f in deny_service_no_security_controls],
		array.concat(
			[f | some f in deny_service_not_monitored],
			[f | some f in deny_no_interconnection_agreement],
		),
	),
)

result := {
	"control_id": "SA-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
