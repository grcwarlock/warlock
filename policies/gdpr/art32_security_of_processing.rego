package gdpr.art32

import rego.v1

# GDPR Article 32: Security of processing
# Encryption, pseudonymisation, resilience, MFA, network controls

deny_no_encryption contains msg if {
	some resource in input.normalized_data.storage_resources
	not resource.encryption_enabled
	msg := sprintf("Art32: Resource '%s' lacks encryption at rest", [resource.name])
}

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	msg := sprintf("Art32: User '%s' does not have MFA enabled", [user.username])
}

deny_open_security_group contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.ingress_rules
	rule.cidr == "0.0.0.0/0"
	rule.port_range_low <= 22
	rule.port_range_high >= 22
	msg := sprintf("Art32: Security group '%s' allows unrestricted SSH access (0.0.0.0/0:22)", [sg.name])
}

deny_open_security_group contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.ingress_rules
	rule.cidr == "0.0.0.0/0"
	rule.port_range_low <= 3389
	rule.port_range_high >= 3389
	msg := sprintf("Art32: Security group '%s' allows unrestricted RDP access (0.0.0.0/0:3389)", [sg.name])
}

default compliant := false

compliant if {
	count(deny_no_encryption) == 0
	count(deny_no_mfa) == 0
	count(deny_open_security_group) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_encryption],
		[f | some f in deny_no_mfa],
	),
	[f | some f in deny_open_security_group],
)

result := {
	"control_id": "Art32",
	"framework": "GDPR",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
