package nist.ca.ca_9

import rego.v1

# CA-9: Internal System Connections
# Validates internal system connections are authorized and documented

deny_no_internal_connection_inventory contains msg if {
	not input.normalized_data.internal_connections
	msg := "CA-9: No internal system connection inventory exists"
}

deny_unauthorized_internal_connection contains msg if {
	some conn in input.normalized_data.internal_connections
	not conn.authorized
	msg := sprintf("CA-9: Internal connection from '%s' to '%s' is not authorized", [conn.source, conn.destination])
}

deny_no_interface_documentation contains msg if {
	some conn in input.normalized_data.internal_connections
	conn.authorized
	not conn.interface_documented
	msg := sprintf("CA-9: Interface characteristics not documented for connection '%s' to '%s'", [conn.source, conn.destination])
}

deny_unrestricted_security_groups contains msg if {
	input.provider == "aws"
	some sg in input.normalized_data.security_groups
	some rule in sg.inbound_rules
	rule.cidr == "0.0.0.0/0"
	rule.port != 443
	rule.port != 80
	msg := sprintf("CA-9: Security group '%s' allows unrestricted inbound access on port %d", [sg.name, rule.port])
}

deny_no_network_segmentation contains msg if {
	input.normalized_data.internal_connections
	not input.normalized_data.network_segmentation_enabled
	msg := "CA-9: Network segmentation is not configured for internal connections"
}

deny_connection_not_reviewed contains msg if {
	some conn in input.normalized_data.internal_connections
	conn.authorized
	conn.last_review_days > 365
	msg := sprintf("CA-9: Internal connection '%s' to '%s' has not been reviewed in %d days", [conn.source, conn.destination, conn.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_internal_connection_inventory) == 0
	count(deny_unauthorized_internal_connection) == 0
	count(deny_unrestricted_security_groups) == 0
	count(deny_no_network_segmentation) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_internal_connection_inventory],
		[f | some f in deny_unauthorized_internal_connection],
	),
	array.concat(
		[f | some f in deny_no_interface_documentation],
		array.concat(
			[f | some f in deny_unrestricted_security_groups],
			array.concat(
				[f | some f in deny_no_network_segmentation],
				[f | some f in deny_connection_not_reviewed],
			),
		),
	),
)

result := {
	"control_id": "CA-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
