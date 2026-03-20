package pci_dss.r4

import rego.v1

# PCI DSS 4.0 Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission

deny_weak_tls contains msg if {
	some endpoint in input.normalized_data.endpoints
	endpoint.tls_version in {"SSLv3", "TLSv1.0", "TLSv1.1"}
	msg := sprintf("R4.1: Endpoint '%s' uses deprecated protocol %s", [endpoint.name, endpoint.tls_version])
}

deny_no_encryption_transit contains msg if {
	some endpoint in input.normalized_data.endpoints
	not endpoint.encryption_in_transit
	msg := sprintf("R4.1: Endpoint '%s' does not encrypt data in transit", [endpoint.name])
}

default compliant := false

compliant if {
	count(deny_weak_tls) == 0
	count(deny_no_encryption_transit) == 0
}

findings := array.concat(
	[f | some f in deny_weak_tls],
	[f | some f in deny_no_encryption_transit],
)

result := {
	"control_id": "R4",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
