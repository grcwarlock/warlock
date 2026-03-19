package iso_27001.a8.a8_20

import rego.v1

# A.8.20: Networks Security
# Validates network security controls including security groups and NACLs

sensitive_ports := {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}

deny_unrestricted_ingress contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	rule.port_range[0] in sensitive_ports
	msg := sprintf("A.8.20: '%s' allows 0.0.0.0/0 ingress on port %d", [rule.group_name, rule.port_range[0]])
}

deny_no_restricted_ssh_rule contains msg if {
	not input.normalized_data.config.restricted_ssh_rule_exists
	msg := "A.8.20: No Config rule monitors for unrestricted SSH access"
}

deny_no_vpc_flow_logs contains msg if {
	some vpc in input.normalized_data.vpcs
	not vpc.flow_logs_enabled
	msg := sprintf("A.8.20: VPC '%s' does not have flow logs enabled", [vpc.id])
}

deny_all_traffic_rule contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.protocol == "all"
	rule.source == "0.0.0.0/0"
	msg := sprintf("A.8.20: '%s' allows all traffic from 0.0.0.0/0", [rule.group_name])
}

default compliant := false

compliant if {
	count(deny_unrestricted_ingress) == 0
	count(deny_all_traffic_rule) == 0
	count(deny_no_vpc_flow_logs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unrestricted_ingress],
		[f | some f in deny_no_restricted_ssh_rule],
	),
	array.concat(
		[f | some f in deny_no_vpc_flow_logs],
		[f | some f in deny_all_traffic_rule],
	),
)

result := {
	"control_id": "A.8.20",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
	"rules_evaluated": count(input.normalized_data.rules),
}
