package iso_27001.a6.a6_07

import rego.v1

# A.6.7: Remote Working
# Validates remote working security controls including VPN and endpoint protection

deny_no_client_vpn contains msg if {
	not input.normalized_data.vpn.client_vpn_configured
	msg := "A.6.7: No Client VPN endpoint configured for secure remote access"
}

deny_vpn_no_logging contains msg if {
	input.normalized_data.vpn.client_vpn_configured
	not input.normalized_data.vpn.connection_logging_enabled
	msg := "A.6.7: Client VPN connection logging is not enabled"
}

deny_no_mfa_for_remote contains msg if {
	some user in input.normalized_data.users
	user.console_access
	not user.mfa_enabled
	msg := sprintf("A.6.7: User '%s' has console access without MFA — insecure for remote working", [user.username])
}

deny_no_remote_working_policy contains msg if {
	not input.normalized_data.policies.remote_working_policy_documented
	msg := "A.6.7: No remote working security policy is documented"
}

deny_vpn_no_auth contains msg if {
	input.normalized_data.vpn.client_vpn_configured
	not input.normalized_data.vpn.mutual_authentication_enabled
	msg := "A.6.7: Client VPN does not use certificate-based mutual authentication"
}

default compliant := false

compliant if {
	count(deny_no_client_vpn) == 0
	count(deny_vpn_no_logging) == 0
	count(deny_no_mfa_for_remote) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_client_vpn],
		[f | some f in deny_vpn_no_logging],
	),
	array.concat(
		[f | some f in deny_no_mfa_for_remote],
		array.concat(
			[f | some f in deny_no_remote_working_policy],
			[f | some f in deny_vpn_no_auth],
		),
	),
)

result := {
	"control_id": "A.6.7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
