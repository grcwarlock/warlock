package hipaa.s164_312.s164_312_e_1

import rego.v1

# 164.312(e)(1): Transmission Security
# Requires technical security measures to guard against unauthorized
# access to ePHI transmitted over an electronic communications network

deny_no_tls_enforcement contains msg if {
	not input.normalized_data.config.tls_enforced
	msg := "164.312(e)(1): TLS is not enforced — must implement encryption to protect ePHI in transit"
}

deny_weak_tls_version contains msg if {
	input.normalized_data.config.tls_enforced
	input.normalized_data.config.min_tls_version < "1.2"
	msg := sprintf("164.312(e)(1): Minimum TLS version is %s — must use TLS 1.2 or higher for ePHI transmission", [input.normalized_data.config.min_tls_version])
}

deny_unencrypted_endpoint contains msg if {
	some endpoint in input.normalized_data.resources.endpoints
	endpoint.handles_ephi
	not endpoint.encryption_in_transit
	msg := sprintf("164.312(e)(1): Endpoint '%s' transmits ePHI without encryption in transit", [endpoint.name])
}

deny_no_integrity_controls_in_transit contains msg if {
	not input.normalized_data.config.transmission_integrity_checks
	msg := "164.312(e)(1): No integrity controls for data in transit — must implement mechanisms to ensure ePHI is not improperly modified during transmission"
}

default compliant := false

compliant if {
	count(deny_no_tls_enforcement) == 0
	count(deny_weak_tls_version) == 0
	count(deny_unencrypted_endpoint) == 0
	count(deny_no_integrity_controls_in_transit) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_tls_enforcement],
		[f | some f in deny_weak_tls_version],
	),
	array.concat(
		[f | some f in deny_unencrypted_endpoint],
		[f | some f in deny_no_integrity_controls_in_transit],
	),
)

result := {
	"control_id": "164.312(e)(1)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
