package nist.sc.sc_8

import rego.v1

# SC-8: Transmission Confidentiality and Integrity
# Protect the confidentiality and integrity of transmitted information.

deny_unencrypted_listeners contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.port_range[0] <= 80
	rule.port_range[1] >= 80
	rule.source == "0.0.0.0/0"
	msg := sprintf("SC-8: Security group '%s' allows unencrypted HTTP (port 80) from any source", [rule.group_name])
}

deny_unencrypted_listeners contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.port_range[0] <= 21
	rule.port_range[1] >= 21
	rule.source == "0.0.0.0/0"
	msg := sprintf("SC-8: Security group '%s' allows unencrypted FTP (port 21) from any source", [rule.group_name])
}

deny_unencrypted_listeners contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.port_range[0] <= 23
	rule.port_range[1] >= 23
	rule.source == "0.0.0.0/0"
	msg := sprintf("SC-8: Security group '%s' allows Telnet (port 23) from any source", [rule.group_name])
}

deny_no_tls contains msg if {
	input.normalized_data.tls_config
	config := input.normalized_data.tls_config
	config.minimum_tls_version < "1.2"
	msg := sprintf("SC-8: Minimum TLS version (%s) is below 1.2", [config.minimum_tls_version])
}

default compliant := false

compliant if {
	count(deny_unencrypted_listeners) == 0
	count(deny_no_tls) == 0
}

findings := array.concat(
	[f | some f in deny_unencrypted_listeners],
	[f | some f in deny_no_tls],
)

result := {
	"control_id": "SC-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
