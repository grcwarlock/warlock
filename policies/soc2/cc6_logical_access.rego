package soc2.cc6

import rego.v1

# SOC 2 CC6.1: Logical and Physical Access Controls
# Maps to NIST AC-2, AC-6

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("CC6.1: User '%s' lacks MFA — logical access control gap", [user.username])
}

deny_excessive_access contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	msg := sprintf("CC6.1: User '%s' has unrestricted access via '%s'", [user.username, policy.name])
}

deny_root_keys contains msg if {
	input.normalized_data.root_account.access_keys_present
	msg := "CC6.1: Root/owner account has programmatic access keys"
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_excessive_access) == 0
	count(deny_root_keys) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_excessive_access],
	),
	[f | some f in deny_root_keys],
)

# CC6.2: Prior to issuing system credentials, registration and authorization
deny_no_provisioning_approval contains msg if {
	some user in input.normalized_data.users
	not user.provisioning_approved
	user.created_within_days <= 30
	msg := sprintf("CC6.2: User '%s' provisioned without documented approval", [user.username])
}

# CC6.3: System credentials are removed when no longer authorized
deny_stale_accounts contains msg if {
	some user in input.normalized_data.users
	user.days_since_last_login > 90
	user.is_active
	msg := sprintf("CC6.3: User '%s' inactive for %d days but account still active", [user.username, user.days_since_last_login])
}

# CC6.5: Logical access security over external connectivity
deny_unrestricted_external_access contains msg if {
	some sg in input.normalized_data.security_groups
	some rule in sg.inbound_rules
	rule.cidr == "0.0.0.0/0"
	rule.port_range == "0-65535"
	msg := sprintf("CC6.5: Security group '%s' allows unrestricted inbound from internet", [sg.id])
}

# CC6.6: Security measures against threats from external sources
deny_no_ids_ips contains msg if {
	not input.normalized_data.network_security.ids_enabled
	not input.normalized_data.network_security.ips_enabled
	msg := "CC6.6: No IDS/IPS enabled — external threat detection gap"
}

# CC6.7: Transmission of data is restricted to authorized channels
deny_unencrypted_transmission contains msg if {
	some endpoint in input.normalized_data.endpoints
	endpoint.protocol == "http"
	not endpoint.internal_only
	msg := sprintf("CC6.7: Endpoint '%s' transmits data over unencrypted HTTP", [endpoint.url])
}

# CC6.8: Controls to prevent or detect unauthorized software
deny_no_software_controls contains msg if {
	not input.normalized_data.endpoint_protection.application_whitelisting
	not input.normalized_data.endpoint_protection.edr_enabled
	msg := "CC6.8: No application control or EDR — unauthorized software not detected"
}

compliant_cc6_2_8 := count(deny_no_provisioning_approval) == 0
compliant_cc6_3 := count(deny_stale_accounts) == 0
compliant_cc6_5 := count(deny_unrestricted_external_access) == 0
compliant_cc6_6 := count(deny_no_ids_ips) == 0
compliant_cc6_7 := count(deny_unencrypted_transmission) == 0
compliant_cc6_8 := count(deny_no_software_controls) == 0

all_findings := array.concat(
	findings,
	array.concat(
		array.concat(
			array.concat(
				[f | some f in deny_no_provisioning_approval],
				[f | some f in deny_stale_accounts],
			),
			array.concat(
				[f | some f in deny_unrestricted_external_access],
				[f | some f in deny_no_ids_ips],
			),
		),
		array.concat(
			[f | some f in deny_unencrypted_transmission],
			[f | some f in deny_no_software_controls],
		),
	),
)

result := {
	"control_id": "CC6",
	"framework": "SOC 2",
	"compliant": compliant,
	"sub_controls": {
		"CC6.1": compliant,
		"CC6.2": compliant_cc6_2_8,
		"CC6.3": compliant_cc6_3,
		"CC6.5": compliant_cc6_5,
		"CC6.6": compliant_cc6_6,
		"CC6.7": compliant_cc6_7,
		"CC6.8": compliant_cc6_8,
	},
	"findings": all_findings,
	"severity": "high",
}
