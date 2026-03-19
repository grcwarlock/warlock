package nist.cp.cp_8

import rego.v1

# CP-8: Telecommunications Services
# Validates redundant telecommunications services for continuity

deny_no_redundant_telecom contains msg if {
	not input.normalized_data.telecommunications
	msg := "CP-8: No alternate telecommunications services configured"
}

deny_single_provider contains msg if {
	input.normalized_data.telecommunications
	input.normalized_data.telecommunications.provider_count < 2
	msg := "CP-8: Only a single telecommunications provider configured — redundant provider required"
}

deny_no_diverse_routing contains msg if {
	input.normalized_data.telecommunications
	not input.normalized_data.telecommunications.diverse_routing_enabled
	msg := "CP-8: Diverse routing for telecommunications is not configured"
}

deny_no_vpn_redundancy contains msg if {
	input.normalized_data.telecommunications
	input.normalized_data.telecommunications.vpn_configured
	not input.normalized_data.telecommunications.vpn_redundancy
	msg := "CP-8: VPN connections do not have redundant paths configured"
}

deny_no_telecom_agreement contains msg if {
	input.normalized_data.telecommunications
	not input.normalized_data.telecommunications.service_agreement_documented
	msg := "CP-8: Alternate telecommunications service agreements are not documented"
}

deny_no_bandwidth_sufficient contains msg if {
	input.normalized_data.telecommunications
	not input.normalized_data.telecommunications.bandwidth_sufficient
	msg := "CP-8: Alternate telecommunications bandwidth is insufficient for essential operations"
}

default compliant := false

compliant if {
	count(deny_no_redundant_telecom) == 0
	count(deny_single_provider) == 0
	count(deny_no_diverse_routing) == 0
	count(deny_no_vpn_redundancy) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_redundant_telecom],
		[f | some f in deny_single_provider],
	),
	array.concat(
		[f | some f in deny_no_diverse_routing],
		array.concat(
			[f | some f in deny_no_vpn_redundancy],
			array.concat(
				[f | some f in deny_no_telecom_agreement],
				[f | some f in deny_no_bandwidth_sufficient],
			),
		),
	),
)

result := {
	"control_id": "CP-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
