package pci_dss.r1

import rego.v1

# PCI DSS 4.0 Requirement 1: Install and Maintain Network Security Controls

deny_open_ingress contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.inbound_rules
	rule.cidr == "0.0.0.0/0"
	rule.port in {22, 3389, 3306, 5432, 1433, 27017, 6379}
	msg := sprintf("R1.2: Security group '%s' allows unrestricted ingress on port %d from 0.0.0.0/0", [sg.id, rule.port])
}

deny_no_firewall contains msg if {
	count(input.normalized_data.security_groups) == 0
	msg := "R1.1: No network security controls (security groups/firewalls) found"
}

deny_all_traffic contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.inbound_rules
	rule.protocol == "-1"
	rule.cidr == "0.0.0.0/0"
	msg := sprintf("R1.2: Security group '%s' allows all traffic from 0.0.0.0/0", [sg.id])
}

default compliant := false

compliant if {
	count(deny_open_ingress) == 0
	count(deny_no_firewall) == 0
	count(deny_all_traffic) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_open_ingress],
		[f | some f in deny_no_firewall],
	),
	[f | some f in deny_all_traffic],
)

result := {
	"control_id": "R1",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
