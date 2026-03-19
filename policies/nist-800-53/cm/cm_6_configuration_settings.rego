package nist.cm.cm_6

import rego.v1

# CM-6: Configuration Settings

deny_default_ports_open contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	default_service_ports := {80, 443, 8080, 8443}
	some port in default_service_ports
	port >= rule.port_range[0]
	port <= rule.port_range[1]
	msg := sprintf("CM-6: Default service port %d exposed to internet on '%s'", [port, rule.group_name])
}

deny_encryption_disabled contains msg if {
	some resource in input.normalized_data.resources
	not resource.encrypted
	msg := sprintf("CM-6: Resource '%s' (%s) does not have encryption enabled", [resource.resource_id, resource.resource_type])
}

default compliant := false

compliant if {
	count(deny_default_ports_open) == 0
	count(deny_encryption_disabled) == 0
}

findings := array.concat(
	[f | some f in deny_default_ports_open],
	[f | some f in deny_encryption_disabled],
)

result := {
	"control_id": "CM-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
