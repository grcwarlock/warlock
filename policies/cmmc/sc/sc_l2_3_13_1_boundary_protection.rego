package cmmc.sc.sc_l2_3_13_1

import rego.v1

# SC.L2-3.13.1: Boundary Protection
# Monitor, control, and protect communications at the external and key internal boundaries of organizational systems

deny_unrestricted_ingress contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.ingress_rules
	rule.source == "0.0.0.0/0"
	rule.port_range != "443"
	rule.port_range != "80"
	msg := sprintf("SC.L2-3.13.1: Security group '%s' allows unrestricted ingress on port %s from 0.0.0.0/0", [sg.name, rule.port_range])
}

deny_no_waf contains msg if {
	some system in input.normalized_data.systems
	system.internet_facing
	not system.waf_enabled
	msg := sprintf("SC.L2-3.13.1: Internet-facing system '%s' does not have a web application firewall enabled", [system.name])
}

deny_no_ids contains msg if {
	some network in input.normalized_data.networks
	network.contains_cui
	not network.intrusion_detection_enabled
	msg := sprintf("SC.L2-3.13.1: CUI network '%s' does not have intrusion detection/prevention enabled", [network.name])
}

deny_no_network_monitoring contains msg if {
	some network in input.normalized_data.networks
	network.contains_cui
	not network.traffic_monitoring_enabled
	msg := sprintf("SC.L2-3.13.1: CUI network '%s' does not have network traffic monitoring enabled", [network.name])
}

default compliant := false

compliant if {
	count(deny_unrestricted_ingress) == 0
	count(deny_no_waf) == 0
	count(deny_no_ids) == 0
	count(deny_no_network_monitoring) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unrestricted_ingress],
		[f | some f in deny_no_waf],
	),
	array.concat(
		[f | some f in deny_no_ids],
		[f | some f in deny_no_network_monitoring],
	),
)

result := {
	"control_id": "SC.L2-3.13.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
