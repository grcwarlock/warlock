package cmmc.ac.ac_l2_3_1_3

import rego.v1

# AC.L2-3.1.3: Control CUI Flow
# Control the flow of CUI in accordance with approved authorizations

deny_no_network_segmentation contains msg if {
	some network in input.normalized_data.networks
	network.contains_cui
	not network.segmented
	msg := sprintf("AC.L2-3.1.3: Network '%s' handles CUI but is not segmented from non-CUI networks", [network.name])
}

deny_no_dlp contains msg if {
	some system in input.normalized_data.systems
	system.processes_cui
	not system.dlp_enabled
	msg := sprintf("AC.L2-3.1.3: System '%s' processes CUI but has no data loss prevention controls", [system.name])
}

deny_unrestricted_egress contains msg if {
	some sg in input.normalized_data.security_groups
	sg.cui_boundary
	some rule in sg.egress_rules
	rule.destination == "0.0.0.0/0"
	rule.protocol == "all"
	msg := sprintf("AC.L2-3.1.3: Security group '%s' on CUI boundary allows unrestricted egress", [sg.name])
}

default compliant := false

compliant if {
	count(deny_no_network_segmentation) == 0
	count(deny_no_dlp) == 0
	count(deny_unrestricted_egress) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_network_segmentation],
		[f | some f in deny_no_dlp],
	),
	[f | some f in deny_unrestricted_egress],
)

result := {
	"control_id": "AC.L2-3.1.3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
