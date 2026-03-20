package pci_dss.r2

import rego.v1

# PCI DSS 4.0 Requirement 2: Apply Secure Configurations to All System Components

deny_default_credentials contains msg if {
	some system in input.normalized_data.systems
	system.default_credentials_present
	msg := sprintf("R2.1: System '%s' has default credentials present", [system.name])
}

deny_unnecessary_services contains msg if {
	some system in input.normalized_data.systems
	some svc in system.unnecessary_services
	msg := sprintf("R2.2: System '%s' has unnecessary service '%s' enabled", [system.name, svc])
}

default compliant := false

compliant if {
	count(deny_default_credentials) == 0
	count(deny_unnecessary_services) == 0
}

findings := array.concat(
	[f | some f in deny_default_credentials],
	[f | some f in deny_unnecessary_services],
)

result := {
	"control_id": "R2",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
