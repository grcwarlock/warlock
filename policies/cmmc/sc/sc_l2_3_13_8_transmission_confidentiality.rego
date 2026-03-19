package cmmc.sc.sc_l2_3_13_8

import rego.v1

# SC.L2-3.13.8: Transmission Confidentiality
# Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission

deny_no_tls contains msg if {
	some system in input.normalized_data.systems
	system.processes_cui
	not system.tls_enforced
	msg := sprintf("SC.L2-3.13.8: CUI system '%s' does not enforce TLS for data in transit", [system.name])
}

deny_weak_tls contains msg if {
	some system in input.normalized_data.systems
	system.tls_enforced
	system.minimum_tls_version < "1.2"
	msg := sprintf("SC.L2-3.13.8: System '%s' allows TLS version below 1.2 — minimum TLS 1.2 required for CUI", [system.name])
}

deny_unencrypted_endpoints contains msg if {
	some endpoint in input.normalized_data.endpoints
	endpoint.handles_cui
	not endpoint.encryption_in_transit
	msg := sprintf("SC.L2-3.13.8: Endpoint '%s' handles CUI without encryption in transit", [endpoint.url])
}

default compliant := false

compliant if {
	count(deny_no_tls) == 0
	count(deny_weak_tls) == 0
	count(deny_unencrypted_endpoints) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_tls],
		[f | some f in deny_weak_tls],
	),
	[f | some f in deny_unencrypted_endpoints],
)

result := {
	"control_id": "SC.L2-3.13.8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
