package ucf.net.ucf_net_1

import rego.v1

# UCF-NET-1: Boundary Protection
# Validates network boundary controls and security groups

sensitive_ports := {22, 3389, 3306, 5432, 1433, 27017, 6379}

deny_open_sg contains msg if {
	some sg in input.normalized_data.security_groups
	some issue in sg.issues
	startswith(issue, "open_to_world")
	msg := sprintf("UCF-NET-1: Security group '%s' has open access: %s", [sg.group_id, issue])
}

default compliant := false

compliant if {
	count(deny_open_sg) == 0
}

findings := [f | some f in deny_open_sg]

result := {
	"control_id": "UCF-NET-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
