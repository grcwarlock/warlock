package cmmc.cm.cm_l2_3_4_6

import rego.v1

# CM.L2-3.4.6: Least Functionality
# Employ the principle of least functionality by configuring systems to provide only essential capabilities

deny_unnecessary_services contains msg if {
	some system in input.normalized_data.systems
	some service in system.running_services
	service.essential == false
	msg := sprintf("CM.L2-3.4.6: System '%s' is running non-essential service '%s'", [system.name, service.name])
}

deny_unnecessary_ports contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.ingress_rules
	rule.port_range == "0-65535"
	msg := sprintf("CM.L2-3.4.6: Security group '%s' allows all ports — restrict to essential services only", [sg.name])
}

deny_unrestricted_software contains msg if {
	some system in input.normalized_data.systems
	not system.software_allowlist_enforced
	system.processes_cui
	msg := sprintf("CM.L2-3.4.6: CUI system '%s' does not enforce a software allowlist", [system.name])
}

default compliant := false

compliant if {
	count(deny_unnecessary_services) == 0
	count(deny_unnecessary_ports) == 0
	count(deny_unrestricted_software) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unnecessary_services],
		[f | some f in deny_unnecessary_ports],
	),
	[f | some f in deny_unrestricted_software],
)

result := {
	"control_id": "CM.L2-3.4.6",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
