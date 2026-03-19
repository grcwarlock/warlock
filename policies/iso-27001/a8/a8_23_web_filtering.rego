package iso_27001.a8.a8_23

import rego.v1

# A.8.23: Web Filtering
# Validates web filtering controls to reduce exposure to malicious content

deny_no_network_firewall contains msg if {
	not input.normalized_data.network_firewall.deployed
	msg := "A.8.23: No AWS Network Firewall deployed for web filtering"
}

deny_no_dns_firewall contains msg if {
	not input.normalized_data.route53resolver.dns_firewall_configured
	msg := "A.8.23: No Route 53 Resolver DNS Firewall configured for domain filtering"
}

deny_no_firewall_rules contains msg if {
	input.normalized_data.network_firewall.deployed
	count(input.normalized_data.network_firewall.rule_groups) == 0
	msg := "A.8.23: Network Firewall is deployed but has no rule groups configured"
}

deny_dns_firewall_no_vpc contains msg if {
	input.normalized_data.route53resolver.dns_firewall_configured
	not input.normalized_data.route53resolver.dns_firewall_associated_to_vpc
	msg := "A.8.23: DNS Firewall is configured but not associated with any VPC"
}

default compliant := false

compliant if {
	count(deny_no_network_firewall) == 0
	count(deny_no_dns_firewall) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_network_firewall],
		[f | some f in deny_no_dns_firewall],
	),
	array.concat(
		[f | some f in deny_no_firewall_rules],
		[f | some f in deny_dns_firewall_no_vpc],
	),
)

result := {
	"control_id": "A.8.23",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
