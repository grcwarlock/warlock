package warlock.fedramp.sc

import rego.v1

# FedRAMP System and Communications Protection

# SC-7: Boundary protection — managed interfaces
deny_no_managed_interfaces contains msg if {
	some interface in input.normalized_data.network.interfaces
	not interface.managed
	msg := sprintf("SC-7: Network interface '%s' not managed at FedRAMP boundary", [interface.id])
}

# SC-8: Transmission confidentiality — FIPS-validated encryption
deny_no_fips_encryption contains msg if {
	some endpoint in input.normalized_data.endpoints
	not endpoint.fips_validated_encryption
	endpoint.handles_federal_data
	msg := sprintf("SC-8: Endpoint '%s' handles federal data without FIPS-validated encryption", [endpoint.url])
}

# SC-12: Cryptographic key management
deny_no_key_management contains msg if {
	not input.normalized_data.encryption.key_management_system
	msg := "SC-12: No cryptographic key management system — required for FedRAMP"
}

# SC-13: Cryptographic protection — FIPS 140-2/3 validated modules
deny_no_fips_modules contains msg if {
	not input.normalized_data.encryption.fips_validated_modules
	msg := "SC-13: Cryptographic modules not FIPS 140-2/3 validated"
}

# SC-28: Protection of information at rest
deny_no_at_rest_encryption contains msg if {
	some storage in input.normalized_data.storage
	storage.contains_federal_data
	not storage.encryption_at_rest
	msg := sprintf("SC-28: Storage '%s' with federal data lacks encryption at rest", [storage.id])
}

default compliant := false

compliant if {
	count(deny_no_managed_interfaces) == 0
	count(deny_no_fips_encryption) == 0
	count(deny_no_key_management) == 0
	count(deny_no_fips_modules) == 0
	count(deny_no_at_rest_encryption) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_managed_interfaces],
		[f | some f in deny_no_fips_encryption],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_key_management],
			[f | some f in deny_no_fips_modules],
		),
		[f | some f in deny_no_at_rest_encryption],
	),
)

result := {
	"control_id": "SC",
	"framework": "FedRAMP",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
