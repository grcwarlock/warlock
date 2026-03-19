package nist.sc.sc_7

import rego.v1

# SC-7: Boundary Protection

sensitive_ports := {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080, 8443}

deny_unrestricted_ingress contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	port_in_range(rule.port_range, sensitive_ports)
	msg := sprintf("SC-7: '%s' allows 0.0.0.0/0 ingress on ports %v", [rule.group_name, rule.port_range])
}

deny_unrestricted_ipv6 contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "::/0"
	port_in_range(rule.port_range, sensitive_ports)
	msg := sprintf("SC-7: '%s' allows ::/0 ingress on ports %v", [rule.group_name, rule.port_range])
}

deny_all_traffic contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.protocol == "all"
	rule.source == "0.0.0.0/0"
	msg := sprintf("SC-7: '%s' allows all traffic from 0.0.0.0/0", [rule.group_name])
}

deny_no_default_deny contains msg if {
	not input.normalized_data.default_deny_inbound
	msg := "SC-7: Network does not implement default deny for inbound traffic"
}

port_in_range(range, ports) if {
	some port in ports
	port >= range[0]
	port <= range[1]
}

default compliant := false

compliant if {
	count(deny_unrestricted_ingress) == 0
	count(deny_unrestricted_ipv6) == 0
	count(deny_all_traffic) == 0
	count(deny_no_default_deny) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unrestricted_ingress],
		[f | some f in deny_unrestricted_ipv6],
	),
	array.concat(
		[f | some f in deny_all_traffic],
		[f | some f in deny_no_default_deny],
	),
)

result := {
	"control_id": "SC-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
	"rules_evaluated": count(input.normalized_data.rules),
}
